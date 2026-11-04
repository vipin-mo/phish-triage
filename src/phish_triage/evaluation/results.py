"""Build docs/RESULTS.md from saved predictions only (no training, no API calls).

    python -m phish_triage.evaluation.results              # 1,000 bootstrap resamples
    python -m phish_triage.evaluation.results --bootstrap 200

Sections: every model on every split; DistilBERT head vs head+tail; PyTorch vs ONNX vs int8; Claude as a
classifier on the fixed 1,000-email sample; and the cascade table. Rows whose predictions don't exist yet are
listed as pending.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score

from phish_triage.data.build import INTERIM_DIR
from phish_triage.evaluation import cascade, metrics, predictions
from phish_triage.evaluation.cascade import run_cascade

RESULTS_PATH = Path("docs/RESULTS.md")
REPORTS_DIR = Path("reports")
SPLITS = (
    "random",
    "by_source/nazario_to_phishing_pot",
    "by_source/phishing_pot_to_nazario",
    "by_time",
    "by_time_nazario",
    "old_era",
)
MODELS = {
    "course": "Course setup (word TF-IDF + LR)",
    "text": "TF-IDF words + chars + LR",
    "features": "Trees on structured features",
    "stacked": "Trees on features + text score",
    "stacked_calibrated": "Stacked, calibrated",
    "distilbert_head": "DistilBERT, first 512 tokens",
    "distilbert_head_tail": "DistilBERT, first 256 + last 256",
    "distilbert_head_int8": "DistilBERT, ONNX int8",
}
LLM_RUNS = {
    "claude_haiku_zero_shot": "Claude Haiku 5.5, no examples",
    "claude_haiku_few_shot": "Claude Haiku 5.5, 4 examples",
    "claude_sonnet_zero_shot": "Claude Sonnet 5.5, no examples",
}
STAGE_1, STAGE_2 = "stacked", "distilbert_head_int8"
CASCADE_LLM = ("claude_haiku_zero_shot", "claude_haiku_few_shot")
EMAILS_PER_DAY = 1_000_000
# Splits each model is trained on (`make train-transformer`); every other model runs on all splits.
EXPECTED = {"distilbert_head_tail": ("random", "by_time"), "distilbert_head_int8": ("random",)}


def labels() -> dict[str, int]:
    index = json.loads((INTERIM_DIR / "index.json").read_text())
    return {e["id"]: int(e["label"] == "phish") for e in index}


def _y(ids: list[str], y: dict[str, int]) -> np.ndarray:
    return np.array([y[i] for i in ids])


def model_table(y: dict[str, int], n_bootstrap: int) -> tuple[list[str], list[str]]:
    lines, pending = [], []
    found = predictions.available()
    for split in SPLITS:
        rows = []
        for model, label in MODELS.items():
            if model not in found.get(split, []):
                if split in EXPECTED.get(model, SPLITS):
                    pending.append(f"`{model}` on `{split}`")
                continue
            p = predictions.load(split, model)
            threshold = metrics.threshold_at_fpr(_y(p.val_ids, y), p.val_scores, 0.01)
            r = metrics.evaluate(
                _y(p.test_ids, y), p.test_scores, threshold=threshold, probabilities=True, n_bootstrap=n_bootstrap
            )
            rows.append(
                f"| {label} | {r.recall_at_fpr['1%']} | {r.recall_at_fpr['0.1%']} | {_pct(r.test_fpr)} | "
                f"{r.precision_at_prevalence} | {r.pr_auc} | {r.ece} |"
            )
        if rows:
            lines += [
                f"### `{split}`",
                "",
                "| Model | Recall @ 1% FPR | Recall @ 0.1% FPR | Test FPR | Precision @ 1 in 100 | PR-AUC | ECE |",
                "|---|---|---|---|---|---|---|",
                *rows,
                "",
            ]
    return lines, pending


def head_vs_tail(y: dict[str, int]) -> list[str]:
    found = predictions.available()
    rows = []
    for split in SPLITS:
        if {"distilbert_head", "distilbert_head_tail"} <= set(found.get(split, [])):
            cells = []
            for model in ("distilbert_head", "distilbert_head_tail"):
                p = predictions.load(split, model)
                yt = _y(p.test_ids, y)
                cells += [
                    f"{metrics.recall_at_fpr(yt, p.test_scores, 0.01):.3f}",
                    f"{metrics.recall_at_fpr(yt, p.test_scores, 0.001):.3f}",
                ]
            rows.append(f"| `{split}` | " + " | ".join(cells) + " |")
    if not rows:
        return ["Pending: needs both DistilBERT variants on the same split.", ""]
    return [
        "| Split | Head: recall @ 1% | Head: recall @ 0.1% | Head + tail: recall @ 1% | Head + tail: recall @ 0.1% |",
        "|---|---:|---:|---:|---:|",
        *rows,
        "",
    ]


def llm_sample() -> list[str] | None:
    """The fixed sample sent to Claude: every email of the largest runs, answered or not."""
    found = set(predictions.available().get("random", []))
    sample: set[str] = set()
    for run in (r for r in LLM_RUNS if r in found):
        p = predictions.load("random", run)
        if p.extra["emails"] >= max(len(sample), 1):
            sample |= set(p.test_ids) | set(p.extra.get("failed", {}))
    return sorted(sample) or None


def llm_section(y: dict[str, int], sample: list[str] | None) -> list[str]:
    found = set(predictions.available().get("random", []))
    if sample is None:
        return ["Pending: the Claude runs haven't been made yet (they need the API key and spend approval).", ""]
    lines = [
        f"On a fixed sample of the `random` test split ({len(sample):,} emails, half phishing; Sonnet on 200 of them). "
        "Local models use their validation threshold for 1% false alarms; Claude flags an email when its phishing "
        "likelihood is 50 or more. Emails Claude didn't answer (safety refusals) are left out of its recall and false "
        "alarms here; in the cascade they fall back to DistilBERT. Cost is at standard (not batch) prices, because "
        "live triage can't wait for a batch.",
        "",
        "| Model | Emails answered | Recall | False alarms | ROC AUC | Cost per 1,000 emails | Latency per email |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    for model in (STAGE_1, STAGE_2):
        if model in found:
            p = predictions.load("random", model)
            score = dict(zip(p.test_ids, p.test_scores, strict=True))
            threshold = metrics.threshold_at_fpr(_y(p.val_ids, y), p.val_scores, 0.01)
            s = np.array([score[i] for i in sample])
            recall, fpr = metrics.rates_at_threshold(_y(sample, y), s, threshold)
            auc = roc_auc_score(_y(sample, y), s)
            lines.append(
                f"| {MODELS[model]} | {len(sample):,} of {len(sample):,} | {recall:.3f} | {fpr:.2%} | {auc:.4f} | "
                f"$0 (local) | {_latency_ms(p.extra)} |"
            )
    for run in (r for r in LLM_RUNS if r in found):
        p = predictions.load("random", run)
        yt = _y(p.test_ids, y)
        recall, fpr = metrics.rates_at_threshold(yt, p.test_scores, 0.495)
        auc = roc_auc_score(yt, p.test_scores)
        lines.append(
            f"| {LLM_RUNS[run]} | {len(p.test_ids):,} of {p.extra['emails']:,} | {recall:.3f} | {fpr:.2%} | "
            f"{auc:.4f} | ${2 * p.extra['cost_per_1000_emails_usd']:.2f} | {_llm_latency(run)} |"
        )
    return lines + [""]


def cascade_section(
    y: dict[str, int], sample: list[str] | None, n_bootstrap: int, split: str = "random", stage_2: str = STAGE_2
) -> list[str]:
    found = set(predictions.available().get(split, []))
    if not {STAGE_1, stage_2} <= found:
        return [f"Pending: needs `{STAGE_1}` and `{stage_2}` predictions on `{split}`.", ""]
    p1, p2 = predictions.load(split, STAGE_1), predictions.load(split, stage_2)
    ids = sample or p1.test_ids
    s1 = dict(zip(p1.test_ids, p1.test_scores, strict=True))
    s2 = dict(zip(p2.test_ids, p2.test_scores, strict=True))
    y_test = _y(ids, y)
    val1 = (_y(p1.val_ids, y), p1.val_scores)
    s2_val = dict(zip(p2.val_ids, p2.val_scores, strict=True))
    val2 = (val1[0], np.array([s2_val[i] for i in p1.val_ids]))
    t1 = metrics.threshold_at_fpr(*val1, 0.01)
    t2 = metrics.threshold_at_fpr(*val2, 0.01)
    lat1 = _latency_value(p1.extra) or _latency_value(predictions.load("random", STAGE_1).extra) or 0.0
    # DistilBERT's latency is measured on the exported int8 model (same network on every split).
    int8 = predictions.load("random", STAGE_2) if STAGE_2 in predictions.available().get("random", []) else None
    lat2 = _latency_value(p2.extra) or (_latency_value(int8.extra) if int8 else None) or 0.0
    test1, test2 = np.array([s1[i] for i in ids]), np.array([s2[i] for i in ids])
    fallback = (test2 > t2).astype(int)  # DistilBERT's own decision, used when the LLM gives no answer

    rows = []

    def add(name, decisions, shares, local_ms, llm_cost_per_email=0.0, llm_seconds=None, without_api="yes"):
        recall = metrics.bootstrap(lambda yy, d: float(d[yy == 1].mean()), y_test, decisions, n_bootstrap)
        fpr = metrics.bootstrap(lambda yy, d: float(d[yy == 0].mean()), y_test, decisions, n_bootstrap)
        precision = metrics.precision_at_prevalence(recall.value, fpr.value)
        cost_1000 = llm_cost_per_email * shares[2] * 1000
        llm_part = f"{llm_seconds:.1f} s" if llm_seconds else "LLM (not measured)"
        if shares[2] == 1.0 and not local_ms:
            latency = llm_part
        else:
            latency = f"{local_ms:.0f} ms" + (f" + {shares[2]:.1%} x {llm_part}" if shares[2] else "")
        stages = f"{shares[0]:.1%} / {shares[1]:.1%} / {shares[2]:.1%}"
        rows.append(
            f"| {name} | {recall} | {_pct(fpr)} | {precision:.3f} | {stages} | {shares[2]:.1%} | {_usd(cost_1000)} | "
            f"{_usd(cost_1000 * EMAILS_PER_DAY / 1000)} | {latency} | {without_api} |"
        )

    stage_2_name = "DistilBERT" if stage_2 == "distilbert_head" else "DistilBERT int8"
    add("Stacked model only", (test1 > t1).astype(int), [1.0, 0.0, 0.0], lat1)
    add(f"{stage_2_name} only", fallback, [0.0, 1.0, 0.0], lat2)
    two_stage = run_cascade([val1], [test1, test2], final_threshold=t2)
    shares2 = two_stage.shares(2) + [0.0]
    add(f"Cascade: stacked -> {stage_2_name}", two_stage.decisions, shares2, lat1 + shares2[1] * lat2)
    # A fairer single-model comparison: the same false-alarm rate as the cascade, with the threshold read off the
    # test set itself (which flatters these rows).
    cascade_fpr = float(two_stage.decisions[y_test == 0].mean())
    for name, scores, shares, ms in (
        ("Stacked", test1, [1.0, 0.0, 0.0], lat1),
        (stage_2_name, test2, [0.0, 1.0, 0.0], lat2),
    ):
        threshold = metrics.threshold_at_fpr(y_test, scores, cascade_fpr)
        add(
            f"{name} only, at the cascade's false-alarm rate (test-tuned)", (scores > threshold).astype(int), shares, ms
        )

    for llm in CASCADE_LLM if split == "random" else ():
        if llm not in found:
            continue
        p3 = predictions.load("random", llm)
        s3 = dict(zip(p3.test_ids, p3.test_scores, strict=True))
        test3 = np.array([s3.get(i, np.nan) for i in ids])
        unanswered = np.isnan(test3)
        per_email = 2 * p3.extra["cost_per_1000_emails_usd"] / 1000
        seconds, _ = _llm_seconds(llm)
        everything = np.where(unanswered, fallback, test3 > 0.495).astype(int)
        add(f"{LLM_RUNS[llm]} on everything", everything, [0.0, 0.0, 1.0], 0.0, per_email, seconds, "no")
        three = run_cascade([val1, val2], [test1, test2, np.nan_to_num(test3)], final_threshold=0.495)
        decisions = np.where((three.stage == 2) & unanswered, fallback, three.decisions)
        shares3 = three.shares(3)
        add(
            f"Cascade: stacked -> {stage_2_name} -> {LLM_RUNS[llm]}",
            decisions,
            shares3,
            lat1 + (shares3[1] + shares3[2]) * lat2,
            per_email,
            seconds,
            "yes (DistilBERT decides)" if shares3[2] else "yes",
        )

    return [
        f"On {len(ids):,} emails of the `{split}` test split. A stage decides an email only when it is confident "
        f"(probability below {cascade.CONFIDENT_SAFE:.0%} or above {cascade.CONFIDENT_PHISH:.0%}) and, on validation, "
        f"marking safe lets through at most {cascade.MAX_MISSED:.1%} of the phishing that reaches it and flagging hits "
        f"at most {cascade.MAX_FALSE_ALARMS:.1%} of the legitimate mail; everything else goes to the next stage. "
        "Latency is the single-email p50 on one CPU thread for each local stage an email passes through, plus the "
        "measured LLM call for the share that reaches it. Emails the LLM doesn't answer fall back to DistilBERT.",
        "",
        "| Setup | Recall | False alarms | Precision @ 1 in 100 | Decided by stage 1 / 2 / LLM | "
        "Sent to a third party | Cost per 1,000 | Cost at 1M emails/day | Typical latency per email | "
        "Works when the LLM API is down |",
        "|---|---|---|---:|---|---:|---:|---:|---|---|",
        *rows,
        "",
    ]


def _usd(amount: float) -> str:
    if amount == 0:
        return "$0"
    return f"${amount:.4f}" if amount < 0.01 else f"${amount:,.2f}"


def _pct(estimate) -> str:
    return f"{estimate.value:.2%} [{estimate.low:.2%}, {estimate.high:.2%}]"


def _latency_value(extra: dict | None) -> float | None:
    latency = (extra or {}).get("latency_ms")
    return latency.get("p50") if latency else None


def _latency_ms(extra: dict | None) -> str:
    value = _latency_value(extra)
    return f"{value:.1f} ms (p50)" if value is not None else "not measured"


def _llm_seconds(run: str) -> tuple[float | None, bool]:
    """(p50 seconds per live call, measured on this run itself). Example-free Haiku stands in for the few-shot run."""
    name = run.removeprefix("claude_")
    for candidate, own in ((name, True), (name.replace("few_shot", "zero_shot"), False)):
        path = Path("data/llm") / f"{candidate}.latency.json"
        if path.exists():
            return json.loads(path.read_text())["p50_s"], own
    return None, False


def _llm_latency(run: str) -> str:
    seconds, own = _llm_seconds(run)
    if seconds is None:
        return "not measured"
    return f"{seconds:.1f} s (p50)" + ("" if own else ", measured without examples")


def build(n_bootstrap: int) -> str:
    y = labels()
    table, pending = model_table(y, n_bootstrap)
    sample = llm_sample()
    llm_lines = llm_section(y, sample)
    onnx = (
        (REPORTS_DIR / "onnx.md").read_text().split("\n", 2)[2] if (REPORTS_DIR / "onnx.md").exists() else "Pending.\n"
    )
    lines = [
        "# Results",
        "",
        "Generated by `make eval` from saved predictions (data/predictions/), so every number here can be rebuilt "
        "without retraining. Brackets are 95% bootstrap intervals. Thresholds are always chosen on the validation "
        "split and applied unchanged to test.",
        "",
        "## 1. Every model on every split",
        "",
        *table,
        "## 2. DistilBERT: first 512 tokens vs first 256 + last 256",
        "",
        *head_vs_tail(y),
        "## 3. PyTorch vs ONNX vs ONNX int8",
        "",
        onnx,
        "## 4. Claude as a classifier",
        "",
        *llm_lines,
        "## 5. The cascade: how much LLM is needed?",
        "",
        "### `random` (the public-data models)",
        "",
        *cascade_section(y, sample, n_bootstrap),
        "### `by_time` (trained on 2015–2022, tested on 2023–2026)",
        "",
        *cascade_section(y, None, n_bootstrap, split="by_time", stage_2="distilbert_head"),
    ]
    if pending:
        lines += ["## Pending", "", "No saved predictions yet for: " + ", ".join(pending) + ".", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bootstrap", type=int, default=metrics.N_BOOTSTRAP)
    args = parser.parse_args(argv)
    text = build(args.bootstrap)
    RESULTS_PATH.write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
