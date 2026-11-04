"""How good and how safe is the analyst step on ordinary emails?

    python -m phish_triage.evaluation.analyst_eval plan            # cost estimate (no API)
    python -m phish_triage.evaluation.analyst_eval run --confirm   # Claude Haiku 5.5, batch (costs money)
    python -m phish_triage.evaluation.analyst_eval rescore         # re-check the saved answers (no API)
    python -m phish_triage.evaluation.analyst_eval ratings         # summarize my ratings once I've filled them in

The defended analyst runs on 200 emails of the fixed Claude sample (half phishing), behind the deployed cascade (its
bundle, one email at a time, as the service runs it). Saved answers are named by prompt version and bundle version,
so a new model or prompt means a new run.
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

from phish_triage.data.records import MASKED_RECORDS, read_analyst_view, read_records
from phish_triage.data.splits import SPLITS_DIR
from phish_triage.evaluation.injection import deployed_classifier
from phish_triage.features.domains import default_ranks
from phish_triage.features.extract import extract
from phish_triage.features.sender import check_sender
from phish_triage.models import llm_batch
from phish_triage.models.llm_classifier import max_llm_spend_usd, sample_ids, spent_usd
from phish_triage.service import analyst

EMAILS = 200
RATED = 50
ANALYST_DIR = Path("data/analyst")
RATING_SHEET = ANALYST_DIR / "rating_sheet.csv"
RATING_EMAILS = ANALYST_DIR / "rating_emails.md"  # each email as the model saw it, then its answer
RUBRIC = ("correct", "grounded", "clear", "useful")  # each scored 1-3, see docs/ANALYST_RUBRIC.md
REPORTS_DIR = Path("reports")


def batch_name(classifier: str) -> str:
    return f"analyst_eval_v{analyst.PROMPT_VERSION}_{classifier}"


def build(emails: int = EMAILS):
    splits = json.loads((SPLITS_DIR / "splits.json").read_text())
    records = read_records(MASKED_RECORDS, set(splits["random"]["test"]))
    ids = sample_ids(splits, emails, {i: r["label"] for i, r in records.items()})
    classify, version = deployed_classifier()
    scored = [classify(records[i]) for i in ids]
    ranks = default_ranks()
    views = read_analyst_view(set(ids))  # the classifier and the signals use the masked record; the analyst this
    params, meaning = {}, {}
    for email_id, (score, flagged) in zip(ids, scored, strict=True):
        record = records[email_id]
        a = analyst.render(
            views[email_id],
            classifier_score=float(score),
            classifier_phish=flagged,
            sender=check_sender(record),
            signals=analyst.signals_from_features(extract(record, ranks)),
        )
        params[email_id] = analyst.request_params(a)
        meaning[email_id] = {"label": record["label"], "flagged": flagged, "_input": a}
    return params, meaning, version


def evaluate(responses: dict, meaning: dict, classifier: str = "") -> tuple[dict, list[dict]]:
    rows, verdicts, indicators, dropped, with_drop, invalid, errors = [], Counter(), 0, 0, 0, 0, Counter()
    from_signals = conflicts = no_action = 0
    for email_id, m in meaning.items():
        raw = responses.get(email_id, {})
        if raw.get("error"):
            errors[raw["error"]] += 1
        refused = raw.get("stop_reason") == "refusal"
        cut_off = raw.get("error") == "max_tokens"
        text = None if raw.get("error") else raw.get("text")
        r = analyst.finish(text, m["_input"], m["flagged"], refused=refused, cut_off=cut_off)
        invalid += not r.schema_valid
        kept = len(r.output.indicators) if r.output else 0
        indicators += kept + r.indicators_dropped
        dropped += r.indicators_dropped
        with_drop += r.indicators_dropped > 0
        from_signals += sum(i.source == "signal" for i in r.output.indicators) if r.output else 0
        no_action += bool(r.output) and r.output.recommended_action == "no_action"
        conflicts += bool(r.output) and analyst.advice_conflict(r.output)
        verdicts[(m["label"], r.verdict)] += 1
        rows.append(
            {
                "id": email_id,
                "label": m["label"],
                "classifier_flagged": m["flagged"],
                "verdict": r.verdict,
                "suggestion": r.output.verdict_suggestion if r.output else "",
                "summary": r.output.summary if r.output else "",
                "action": r.output.recommended_action.replace("_", " ") if r.output else "",
                "indicators": " | ".join(
                    f"[{i.type}] {analyst.shown_evidence(i, m['_input'])} -> {i.why}" for i in r.output.indicators
                )
                if r.output
                else "",
                "dropped": r.indicators_dropped,
                "_shown": m["_input"].shown,  # underscored: for the email file, not the CSV
                "_signals": m["_input"].signals,
            }
        )
    n = len(meaning)
    summary = {
        "prompt_version": analyst.PROMPT_VERSION,
        "llm_model": analyst.MODEL,
        "classifier": classifier,
        "emails": n,
        "schema_valid_rate": (n - invalid) / n,
        "indicators": indicators,
        "grounding_failures": dropped,
        "grounding_failure_rate": dropped / indicators if indicators else 0.0,
        "kept_indicators_citing_a_signal": from_signals,
        "answers_with_a_dropped_indicator": with_drop,
        "no_action_answers": no_action,
        "no_action_with_advice_in_summary": conflicts,
        "errors": dict(errors),
        "verdicts": {f"{label} -> {verdict}": c for (label, verdict), c in sorted(verdicts.items())},
    }
    return summary, rows


def measure_latency(params: dict[str, dict], client, batch: str, emails: int = 20) -> dict:
    """Seconds per email with ordinary (not batch) calls, one at a time; cost recorded in the spend ledger."""
    import time

    import numpy as np

    from phish_triage.models.llm_classifier import check_budget, cost_usd, record_spend, worst_case_usd

    path = Path("data/llm") / f"{batch}.latency.json"
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
    record_spend({"run": f"{batch}_latency", "model": analyst.MODEL, "emails": len(chosen), "cost_usd": cost})
    result = {"p50": float(np.percentile(timings, 50)), "p95": float(np.percentile(timings, 95)), "cost_usd": cost}
    path.write_text(json.dumps(result) + "\n")
    return result


def write_rating_sheet(rows: list[dict], n: int = RATED) -> Path:
    """Half phishing, half legitimate, in sample order; blank columns for my scores; scores already entered are kept
    when the sheet is rewritten, if the answer is the same. The emails go to RATING_EMAILS, numbered like the rows,
    so I read each first."""
    phish = [r for r in rows if r["label"] == "phish"][: n // 2]
    legit = [r for r in rows if r["label"] == "legit"][: n - len(phish)]
    chosen = phish + legit
    ANALYST_DIR.mkdir(parents=True, exist_ok=True)
    scored = {}
    if RATING_SHEET.exists():
        # a score belongs to one answer: kept only if the same email got the same verdict, action, summary and
        # indicators, so a score never attaches to an answer I didn't see
        scored = {_answer(r): {k: r.get(k, "") for k in (*RUBRIC, "notes")} for r in _read_sheet(RATING_SHEET)}
    columns = ["row", *(k for k in rows[0] if not k.startswith("_"))]
    kept = 0
    with RATING_SHEET.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[*columns, *RUBRIC, "notes"])
        writer.writeheader()
        for number, row in enumerate(chosen, 1):
            blank = {**dict.fromkeys(RUBRIC, ""), "notes": ""}
            score = scored.get(_answer(row), blank)
            kept += score is not blank and any(score[k].strip() for k in RUBRIC)
            writer.writerow({"row": number, **{k: row[k] for k in columns[1:]}, **score})
    had = sum(any(s[k].strip() for k in RUBRIC) for s in scored.values())
    if had:
        print(f"rating sheet: kept {kept} of {had} scored rows; {had - kept} dropped (answer changed)", file=sys.stderr)
    RATING_EMAILS.write_text(_rating_emails(chosen))
    return RATING_SHEET


ANSWER_FIELDS = ("id", "verdict", "action", "summary", "indicators")  # what I rate; a change here voids the score


def _answer(row: dict) -> tuple[str, ...]:
    return tuple(row.get(k, "") for k in ANSWER_FIELDS)


def _read_sheet(path: Path) -> list[dict]:
    # utf-8-sig: spreadsheet apps add a byte-order mark; the header check catches a title line added above it
    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        missing = [k for k in ("id", "label", *RUBRIC) if k not in (reader.fieldnames or [])]
        if missing:
            raise SystemExit(
                f"{path}: first line must be the header row (missing {', '.join(missing)}); "
                "remove anything a spreadsheet app added above it"
            )
        return list(reader)


def _rating_emails(chosen: list[dict]) -> str:
    fence = "~~~~"  # emails may contain backticks
    parts = [
        "# Emails to rate\n\nFor each one: read the email, then the answer, then score the row with the same number in "
        "rating_sheet.csv (docs/ANALYST_RUBRIC.md). The email is what the model saw: hidden parts removed, personal "
        "data masked.\n"
    ]
    for number, row in enumerate(chosen, 1):
        signals = "\n".join(f"- [S{i}] {s}" for i, s in enumerate(row["_signals"], 1))
        indicators = "\n".join(f"- {i}" for i in row["indicators"].split(" | ")) if row["indicators"] else "- (none)"
        parts.append(
            f"\n---\n\n## {number}. {row['id']} (true label: {row['label']})\n\n"
            f"### Email\n\n{fence}text\n{row['_shown']}\n{fence}\n\n### Our signals\n\n{signals}\n\n"
            f"### Answer\n\n**Final verdict:** {row['verdict']} "
            f"(the analyst suggested {row['suggestion'] or 'nothing'})\n\n"
            f"**Summary:** {row['summary']}\n\n**Recommended action:** {row['action'] or 'none'}\n\n"
            f"**Indicators:**\n\n{indicators}\n"
        )
    return "".join(parts)


def summarize_ratings(path: Path = RATING_SHEET) -> dict:
    rows = _read_sheet(path)
    bad = [r["row"] for r in rows if any(r[k].strip() not in ("", "1", "2", "3") for k in RUBRIC)]  # partly scored too
    rated = [r for r in rows if all(r[k].strip() for k in RUBRIC)]
    if bad:
        raise SystemExit(f"{path}: scores must be 1, 2 or 3 (rows {', '.join(bad)})")

    def averages(subset: list[dict]) -> dict:
        return {
            "rated": len(subset),
            **{k: round(sum(int(r[k]) for r in subset) / len(subset), 2) for k in RUBRIC},
            "all_three_on_every_criterion": sum(all(int(r[k]) == 3 for k in RUBRIC) for r in subset),
        }

    if not rated:
        return {"rated": 0}
    groups = {label: [r for r in rated if r["label"] == label] for label in ("phish", "legit")}
    return {**averages(rated), "by_label": {label: averages(g) for label, g in groups.items() if g}}


def to_markdown(s: dict) -> str:
    verdict_rows = "\n".join(f"| {k} | {v} |" for k, v in s["verdicts"].items())
    return (
        "# Analyst step on ordinary emails\n\n"
        "Generated by `python -m phish_triage.evaluation.analyst_eval run`. Claude Haiku 5.5 behind the deployed "
        f"cascade (bundle `{s['classifier']}`, one email at a time, as the service runs it), on {s['emails']} emails "
        "of the fixed sample (half phishing). "
        f"Analyst prompt version {s['prompt_version']}.\n\n"
        "| Measure | Value |\n|---|---:|\n"
        f"| Schema-valid answers, first try | {s.get('schema_valid_first_try', s['schema_valid_rate']):.1%} |\n"
        f"| Schema-valid answers, after asking once more ({s.get('retried', 0)} asked) | "
        f"{s['schema_valid_rate']:.1%} |\n"
        f"| Indicators returned | {s['indicators']:,} |\n"
        f"| Grounding failures (dropped) | {s['grounding_failures']} ({s['grounding_failure_rate']:.1%}) |\n"
        f"| Answers with at least one dropped indicator | {s['answers_with_a_dropped_indicator']} |\n"
        f"| Kept indicators that cite one of our signals | {s.get('kept_indicators_citing_a_signal', 0)} |\n"
        f'| "No action" answers whose summary still advises a check | '
        f"{s.get('no_action_with_advice_in_summary', 0)} of {s.get('no_action_answers', 0)} |\n"
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
    params, meaning, version = build()
    batch = batch_name(version)
    if args.command == "plan":
        print(
            f"{len(params)} requests; worst case ${llm_batch.worst_case(params):.2f}; "
            f"spent so far ${spent_usd():.2f}; cap ${max_llm_spend_usd():.2f}"
        )
        return 0
    client = None
    if args.command == "rescore":  # re-apply the checks to the saved answers; no API calls
        llm_batch.check_fingerprint(batch, params)
        responses = llm_batch.load_saved(batch)
    elif not args.confirm:
        parser.error("this calls the Claude API and costs money; add --confirm")
    else:
        from phish_triage.models.llm_classifier import _client

        client = _client()
        responses = llm_batch.run(batch, params, client)
        measure_latency(params, client, batch)
    first_try, _ = evaluate(responses, meaning, version)
    valid = lambda raw: analyst.parse_answer(raw) is not None  # noqa: E731
    responses, retried = llm_batch.retry_invalid(batch, params, responses, valid, client)
    summary, rows = evaluate(responses, meaning, version)
    summary["schema_valid_first_try"] = first_try["schema_valid_rate"]
    summary["retried"] = retried
    latency_path = Path("data/llm") / f"{batch}.latency.json"
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
