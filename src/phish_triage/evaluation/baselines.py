"""Train every baseline on every split and report them with the project's metrics.

    python -m phish_triage.evaluation.baselines                 # every split
    python -m phish_triage.evaluation.baselines random by_time  # some splits
    python -m phish_triage.evaluation.baselines --bootstrap 200 # faster, wider-grained intervals

For each split: fit on `train`, choose each model's threshold on `val` for a 1% false-alarm rate, then measure
`test`. Models trained on the `random` split are also run on the spam slice (how much spam they would flag as
phishing); models trained on `by_time` are drawn in a reliability plot (newer mail is where calibration drifts).

Writes reports/baselines.json, reports/baselines.md and reports/figures/reliability_by_time.png. Only aggregate
numbers are written, never email content.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score

from phish_triage.data.records import MASKED_RECORDS, read_records
from phish_triage.data.splits import SPLITS_DIR
from phish_triage.evaluation import metrics, predictions
from phish_triage.features.domains import default_ranks
from phish_triage.features.extract import FEATURE_NAMES, matrix
from phish_triage.models.baselines import email_text, fit_all

REPORTS_DIR = Path("reports")
SPLITS = (
    "random",
    "by_source/nazario_to_phishing_pot",
    "by_source/phishing_pot_to_nazario",
    "by_time",
    "by_time_nazario",
    "old_era",
)
MODEL_LABELS = {
    "course": "Course setup (word TF-IDF + LR)",
    "text": "TF-IDF words + chars + LR",
    "features": "Trees on structured features",
    "stacked": "Trees on features + text score",
    "text_calibrated": "TF-IDF + LR, calibrated",
    "stacked_calibrated": "Stacked, calibrated",
}
FEATURE_CHECK_SPLITS = ("random", "by_source/nazario_to_phishing_pot", "by_source/phishing_pot_to_nazario")
RELIABILITY_SPLIT = "by_time"
RELIABILITY_MIN_BIN = 20  # bins with fewer test emails are too noisy to draw


def run(split_names: list[str], n_bootstrap: int) -> dict:
    splits = json.loads((SPLITS_DIR / "splits.json").read_text())
    ids = {i for name in split_names for part in splits[name].values() for i in part} | set(splits["spam"]["test"])
    started = time.time()
    records = read_records(MASKED_RECORDS, ids)
    ranks = default_ranks()
    texts = {i: email_text(r) for i, r in records.items()}
    features = dict(zip(records, matrix(list(records.values()), ranks), strict=True))
    labels = {i: int(r["label"] == "phish") for i, r in records.items()}
    print(f"prepared {len(records)} emails in {time.time() - started:.0f}s", file=sys.stderr)

    def part(name: str, which: str):
        members = splits[name][which]
        return (
            [texts[i] for i in members],
            np.array([features[i] for i in members]),
            np.array([labels[i] for i in members]),
        )

    results: dict = {"splits": {}, "spam": {}, "feature_signal": {}, "n_bootstrap": n_bootstrap}
    for name in split_names:
        started = time.time()
        train, val, test = part(name, "train"), part(name, "val"), part(name, "test")
        fitted = fit_all(*train, *val)
        val_scores, test_scores = fitted.scores(val[0], val[1]), fitted.scores(test[0], test[1])
        thresholds = {m: metrics.threshold_at_fpr(val[2], s, 0.01) for m, s in val_scores.items()}
        extra: dict[str, dict] = {m: {} for m in MODEL_LABELS}
        results["splits"][name] = {
            m: metrics.evaluate(
                test[2], test_scores[m], threshold=thresholds[m], probabilities=True, n_bootstrap=n_bootstrap
            ).to_dict()
            for m in MODEL_LABELS
        }
        if name == "random":
            spam_texts, spam_features, _ = part("spam", "test")
            spam_scores = fitted.scores(spam_texts, spam_features)
            results["spam"] = {m: float(np.mean(spam_scores[m] > thresholds[m])) for m in MODEL_LABELS}
            latency = _latency(fitted, splits[name]["test"], records, ranks)
            for m in MODEL_LABELS:
                extra[m] |= {"spam_ids": splits["spam"]["test"], "spam_scores": spam_scores[m].tolist()}
                extra[m] |= {"latency_ms": latency.get(m)} if m in latency else {}
        if name == RELIABILITY_SPLIT:
            _reliability_plot(test[2], test_scores, name)
        if name in FEATURE_CHECK_SPLITS:
            results["feature_signal"][name] = _feature_signal(test[1], test[2])
        for m in MODEL_LABELS:
            predictions.save(
                predictions.Predictions(
                    m, name, splits[name]["val"], val_scores[m], splits[name]["test"], test_scores[m], extra[m]
                )
            )
        print(f"{name}: {time.time() - started:.0f}s", file=sys.stderr)
    return results


def _latency(fitted, ids: list[str], records: dict, ranks, emails: int = 300) -> dict[str, dict]:
    """Per-email CPU latency in ms, one email at a time, from the record (features and TF-IDF included)."""
    sample = ids[:emails]
    timings: dict[str, list[float]] = {"text": [], "stacked": []}
    for i in sample:
        started = time.perf_counter()
        fitted.text.predict_proba([email_text(records[i])])
        timings["text"].append((time.perf_counter() - started) * 1000)
        started = time.perf_counter()
        text_score = fitted.text.predict_proba([email_text(records[i])])[:, 1]
        fitted.stacked.predict_proba(np.column_stack([matrix([records[i]], ranks), text_score]))
        timings["stacked"].append((time.perf_counter() - started) * 1000)
    return {
        m: {"p50": float(np.percentile(t, 50)), "p95": float(np.percentile(t, 95)), "emails": len(t)}
        for m, t in timings.items()
    }


def _feature_signal(x: np.ndarray, y: np.ndarray) -> dict[str, float]:
    """ROC AUC of each feature on its own (no training): above 0.5 means higher values lean phishing."""
    signal = {}
    for j, name in enumerate(FEATURE_NAMES):
        column = x[:, j]
        known = ~np.isnan(column)
        if known.sum() and len(set(y[known])) == 2 and len(set(column[known])) > 1:
            signal[name] = round(float(roc_auc_score(y[known], column[known])), 3)
    return signal


def _reliability_plot(y: np.ndarray, scores: dict[str, np.ndarray], split: str) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(5.5, 5), dpi=150)
    ax.plot([0, 1], [0, 1], color="#999999", linewidth=1, linestyle="--", label="Perfectly calibrated")
    for model, color in (
        ("text", "#4C78A8"),
        ("text_calibrated", "#72B7B2"),
        ("stacked", "#E45756"),
        ("stacked_calibrated", "#F58518"),
    ):
        curve = [b for b in metrics.reliability_curve(y, scores[model]) if b["count"] >= RELIABILITY_MIN_BIN]
        ece = metrics.expected_calibration_error(y, scores[model])
        xs, ys = [b["mean_predicted"] for b in curve], [b["observed"] for b in curve]
        ax.plot(xs, ys, color=color, linewidth=1.5, label=f"{MODEL_LABELS[model]} (ECE {ece:.3f})")
        ax.scatter(xs, ys, s=[4 + 40 * b["count"] / len(y) for b in curve], color=color, zorder=3)
    ax.set(xlabel="Predicted probability of phishing", ylabel="Observed share of phishing", xlim=(0, 1), ylim=(0, 1))
    ax.set_title(f"Reliability on the {split} test part (bins with {RELIABILITY_MIN_BIN}+ emails)", fontsize=10)
    ax.legend(fontsize=7, loc="upper left", frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    (REPORTS_DIR / "figures").mkdir(parents=True, exist_ok=True)
    fig.savefig(REPORTS_DIR / "figures" / f"reliability_{split}.png")
    plt.close(fig)


def to_markdown(results: dict) -> str:
    lines = [
        "# Baseline models",
        "",
        "Generated by `make eval-baselines`. Each model is trained on a split's `train` part; its threshold is "
        "chosen on `val` for a 1% false-alarm rate and then applied unchanged to `test`. Brackets are 95% "
        f"bootstrap intervals ({results['n_bootstrap']} class-stratified resamples).",
        "",
        "- **Recall @ 1% / 0.1% FPR:** share of phishing caught while flagging at most 1% / 0.1% of legitimate mail, "
        "read off the test ROC curve.",
        "- **Test FPR:** the false-alarm rate the validation threshold really gives on test.",
        "- **Precision @ 1 in 100:** precision at that threshold if 1 email in 100 were phishing.",
        "- **Calibrated rows** change only the probabilities (ECE). Their ranking, and so every other column, matches "
        "the uncalibrated model, because isotonic ties are broken by the uncalibrated score.",
        "",
    ]
    for name, models in results["splits"].items():
        first = next(iter(models.values()))
        lines += [
            f"## `{name}` ({first['n_phish']:,} phishing / {first['n_legit']:,} legitimate in test)",
            "",
            "| Model | PR-AUC | Recall @ 1% FPR | Recall @ 0.1% FPR | Test FPR | Precision @ 1 in 100 | ECE |",
            "|---|---|---|---|---|---|---|",
        ]
        for model, r in models.items():
            cells = [
                _fmt(r["pr_auc"]),
                _fmt(r["recall_at_fpr"]["1%"]),
                _fmt(r["recall_at_fpr"]["0.1%"]),
                _fmt(r["test_fpr"], pct=True),
                _fmt(r["precision_at_prevalence"]),
                _fmt(r["ece"]),
            ]
            lines.append(f"| {MODEL_LABELS[model]} | " + " | ".join(cells) + " |")
        lines.append("")
    if results["spam"]:
        lines += [
            "## Spam flagged as phishing (models trained on `random`, at their 1% thresholds)",
            "",
            "| Model | Share of spam flagged |",
            "|---|---:|",
        ]
        lines += [f"| {MODEL_LABELS[m]} | {share:.1%} |" for m, share in results["spam"].items()]
        lines += ["", f"![Reliability plot](figures/reliability_{RELIABILITY_SPLIT}.png)", ""]
    if results["feature_signal"]:
        names = list(results["feature_signal"])
        lines += [
            "## Each structured feature on its own (test ROC AUC, no training)",
            "",
            "Above 0.5: higher values lean phishing. A feature that separates `random` but not the cross-source "
            "tests is learning the dataset, not phishing.",
            "",
            "| Feature | " + " | ".join(f"`{n}`" for n in names) + " |",
            "|---|" + "---:|" * len(names),
        ]
        for feature in FEATURE_NAMES:
            values = [results["feature_signal"][n].get(feature) for n in names]
            lines.append(f"| `{feature}` | " + " | ".join("" if v is None else f"{v:.3f}" for v in values) + " |")
        lines.append("")
    return "\n".join(lines)


def _fmt(estimate: dict | None, pct: bool = False) -> str:
    if estimate is None:
        return ""
    if pct:
        return f"{estimate['value']:.2%} ({estimate['low']:.2%}–{estimate['high']:.2%})"
    return f"{estimate['value']:.3f} ({estimate['low']:.3f}–{estimate['high']:.3f})"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("splits", nargs="*", help=f"any of: {', '.join(SPLITS)} (default: all)")
    parser.add_argument("--bootstrap", type=int, default=metrics.N_BOOTSTRAP, help="bootstrap resamples")
    args = parser.parse_args(argv)
    if unknown := set(args.splits) - set(SPLITS):
        parser.error(f"unknown split(s): {', '.join(sorted(unknown))}")
    results = run(args.splits or list(SPLITS), args.bootstrap)
    REPORTS_DIR.mkdir(exist_ok=True)
    (REPORTS_DIR / "baselines.json").write_text(json.dumps(results, indent=1) + "\n")
    (REPORTS_DIR / "baselines.md").write_text(to_markdown(results))
    print(to_markdown(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
