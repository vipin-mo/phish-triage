"""How good and how safe is the analyst step on ordinary emails?

    python -m phish_triage.evaluation.analyst_eval plan            # cost estimate (no API)
    python -m phish_triage.evaluation.analyst_eval run --confirm   # Claude Haiku 5.5, batch (costs money)
    python -m phish_triage.evaluation.analyst_eval rescore         # re-check the saved answers (no API)
    python -m phish_triage.evaluation.analyst_eval ratings         # summarize my ratings once I've filled them in

The defended analyst runs on 200 emails of the fixed Claude sample (half phishing), behind DistilBERT int8.
Measured: schema-valid rate, grounding failures (indicators dropped because their quote wasn't in the email or their
URL wasn't one the extractor found), final verdicts against the true labels, and cost.

It also writes a rating sheet for 50 of the summaries (data/analyst/rating_sheet.csv, local only, because it quotes
dataset emails), which I score by hand on the rubric in docs/ANALYST_RUBRIC.md.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

from phish_triage.data.records import MASKED_RECORDS, read_records
from phish_triage.data.splits import SPLITS_DIR
from phish_triage.evaluation.injection import distilbert_scorer
from phish_triage.features.domains import default_ranks
from phish_triage.features.extract import extract
from phish_triage.features.sender import check_sender
from phish_triage.models import llm_batch
from phish_triage.models.baselines import email_text
from phish_triage.models.llm_classifier import max_llm_spend_usd, sample_ids, spent_usd
from phish_triage.service import analyst

EMAILS = 200
RATED = 50
ANALYST_DIR = Path("data/analyst")
RATING_SHEET = ANALYST_DIR / "rating_sheet.csv"
RUBRIC = ("correct", "grounded", "clear", "useful")  # each scored 1-3, see docs/ANALYST_RUBRIC.md
REPORTS_DIR = Path("reports")
BATCH = f"analyst_eval_v{analyst.PROMPT_VERSION}"


def build(emails: int = EMAILS):
    splits = json.loads((SPLITS_DIR / "splits.json").read_text())
    records = read_records(MASKED_RECORDS, set(splits["random"]["test"]))
    ids = sample_ids(splits, emails, {i: r["label"] for i, r in records.items()})
    classifier, threshold = distilbert_scorer()
    scores = classifier.score([email_text(records[i]) for i in ids])
    ranks = default_ranks()
    params, meaning = {}, {}
    for email_id, score in zip(ids, scores, strict=True):
        record = records[email_id]
        a = analyst.render(
            record,
            classifier_score=float(score),
            classifier_phish=bool(score > threshold),
            sender=check_sender(record),
            signals=analyst.signals_from_features(extract(record, ranks)),
        )
        params[email_id] = analyst.request_params(a)
        meaning[email_id] = {"label": record["label"], "flagged": bool(score > threshold), "_input": a}
    return params, meaning


def evaluate(responses: dict, meaning: dict) -> tuple[dict, list[dict]]:
    rows, verdicts, indicators, dropped, with_drop, invalid, errors = [], Counter(), 0, 0, 0, 0, Counter()
    from_signals = 0
    for email_id, m in meaning.items():
        raw = responses.get(email_id, {})
        if raw.get("error"):
            errors[raw["error"]] += 1
        r = analyst.finish(None if raw.get("error") else raw.get("text"), m["_input"], m["flagged"])
        invalid += not r.schema_valid
        kept = len(r.output.indicators) if r.output else 0
        indicators += kept + r.indicators_dropped
        dropped += r.indicators_dropped
        with_drop += r.indicators_dropped > 0
        from_signals += sum(i.source == "signal" for i in r.output.indicators) if r.output else 0
        verdicts[(m["label"], r.verdict)] += 1
        rows.append(
            {
                "id": email_id,
                "label": m["label"],
                "classifier_flagged": m["flagged"],
                "verdict": r.verdict,
                "suggestion": r.output.verdict_suggestion if r.output else "",
                "summary": r.output.summary if r.output else "",
                "indicators": " | ".join(
                    f"[{i.type}] {analyst.shown_evidence(i, m['_input'])} -> {i.why}" for i in r.output.indicators
                )
                if r.output
                else "",
                "dropped": r.indicators_dropped,
            }
        )
    n = len(meaning)
    summary = {
        "prompt_version": analyst.PROMPT_VERSION,
        "emails": n,
        "schema_valid_rate": (n - invalid) / n,
        "indicators": indicators,
        "grounding_failures": dropped,
        "grounding_failure_rate": dropped / indicators if indicators else 0.0,
        "kept_indicators_citing_a_signal": from_signals,
        "answers_with_a_dropped_indicator": with_drop,
        "errors": dict(errors),
        "verdicts": {f"{label} -> {verdict}": c for (label, verdict), c in sorted(verdicts.items())},
    }
    return summary, rows


def measure_latency(params: dict[str, dict], client, emails: int = 20) -> dict:
    """Seconds per email with ordinary (not batch) calls, one at a time; cost recorded in the spend ledger."""
    import time

    import numpy as np

    from phish_triage.models.llm_classifier import check_budget, cost_usd, record_spend, worst_case_usd

    path = Path("data/llm") / f"{BATCH}.latency.json"
    if path.exists():
        return json.loads(path.read_text())
    chosen = list(params)[:emails]
    check_budget(worst_case_usd(analyst.MODEL, 4_000 * emails, emails, batch=False) * 2, max_llm_spend_usd())
    timings, cost = [], 0.0
    for email_id in chosen:
        started = time.perf_counter()
        message = client.messages.create(**params[email_id])
        timings.append(time.perf_counter() - started)
        cost += cost_usd(analyst.MODEL, message.usage, batch=False)
    record_spend({"run": f"{BATCH}_latency", "model": analyst.MODEL, "emails": len(chosen), "cost_usd": cost})
    result = {"p50": float(np.percentile(timings, 50)), "p95": float(np.percentile(timings, 95)), "cost_usd": cost}
    path.write_text(json.dumps(result) + "\n")
    return result


def write_rating_sheet(rows: list[dict], n: int = RATED) -> Path:
    """Half phishing, half legitimate, in sample order; blank columns for my scores."""
    phish = [r for r in rows if r["label"] == "phish"][: n // 2]
    legit = [r for r in rows if r["label"] == "legit"][: n - len(phish)]
    ANALYST_DIR.mkdir(parents=True, exist_ok=True)
    with RATING_SHEET.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[*rows[0], *RUBRIC, "notes"])
        writer.writeheader()
        for row in phish + legit:
            writer.writerow({**row, **dict.fromkeys(RUBRIC, ""), "notes": ""})
    return RATING_SHEET


def summarize_ratings(path: Path = RATING_SHEET) -> dict:
    with path.open(newline="") as f:
        rated = [r for r in csv.DictReader(f) if all(r[k].strip() for k in RUBRIC)]
    if not rated:
        return {"rated": 0}
    return {
        "rated": len(rated),
        **{k: sum(int(r[k]) for r in rated) / len(rated) for k in RUBRIC},
        "all_three_on_every_criterion": sum(all(int(r[k]) == 3 for k in RUBRIC) for r in rated),
    }


def to_markdown(s: dict) -> str:
    verdict_rows = "\n".join(f"| {k} | {v} |" for k, v in s["verdicts"].items())
    return (
        "# Analyst step on ordinary emails\n\n"
        "Generated by `python -m phish_triage.evaluation.analyst_eval run`. Claude Haiku 5.5 behind DistilBERT int8, "
        f"on {s['emails']} emails of the fixed sample (half phishing). "
        f"Analyst prompt version {s['prompt_version']}.\n\n"
        "| Measure | Value |\n|---|---:|\n"
        f"| Schema-valid answers | {s['schema_valid_rate']:.1%} |\n"
        f"| Indicators returned | {s['indicators']:,} |\n"
        f"| Grounding failures (dropped) | {s['grounding_failures']} ({s['grounding_failure_rate']:.1%}) |\n"
        f"| Answers with at least one dropped indicator | {s['answers_with_a_dropped_indicator']} |\n"
        f"| Kept indicators that cite one of our signals | {s.get('kept_indicators_citing_a_signal', 0)} |\n"
        f"| Errors (refusals, limits) | {sum(s['errors'].values())} |\n"
        + (
            f"| Latency per email, live call (p50 / p95) | {s['latency_s']['p50']:.1f} s / "
            f"{s['latency_s']['p95']:.1f} s |\n"
            if s.get("latency_s")
            else ""
        )
        + "\n"
        "| True label -> final verdict | Emails |\n|---|---:|\n" + verdict_rows + "\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("plan", "run", "rescore", "ratings"))
    parser.add_argument("--confirm", action="store_true", help="call the Claude API (costs money)")
    args = parser.parse_args(argv)
    if args.command == "ratings":
        print(json.dumps(summarize_ratings(), indent=1))
        return 0
    params, meaning = build()
    if args.command == "plan":
        print(
            f"{len(params)} requests; worst case ${llm_batch.worst_case(params):.2f}; "
            f"spent so far ${spent_usd():.2f}; cap ${max_llm_spend_usd():.2f}"
        )
        return 0
    if args.command == "rescore":  # re-apply the checks to the saved answers; no API calls
        responses = llm_batch.load_saved(BATCH)
    elif not args.confirm:
        parser.error("this calls the Claude API and costs money; add --confirm")
    else:
        from phish_triage.models.llm_classifier import _client

        client = _client()
        responses = llm_batch.run(BATCH, params, client)
        measure_latency(params, client)
    summary, rows = evaluate(responses, meaning)
    latency_path = Path("data/llm") / f"{BATCH}.latency.json"
    if latency_path.exists():
        summary["latency_s"] = json.loads(latency_path.read_text())
    REPORTS_DIR.mkdir(exist_ok=True)
    (REPORTS_DIR / "analyst.json").write_text(json.dumps(summary, indent=1) + "\n")
    (REPORTS_DIR / "analyst.md").write_text(to_markdown(summary))
    print(to_markdown(summary))
    print(f"rating sheet: {write_rating_sheet(rows)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
