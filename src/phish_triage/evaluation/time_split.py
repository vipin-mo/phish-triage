"""Phishing from months after training: a candidate trained on phishing up to July 2026 (reports/time_split.md).

    python -m phish_triage.evaluation.time_split build      # the candidate bundle (after `make train-time-split`)
    python -m phish_triage.evaluation.time_split measure    # $0; nothing goes to an LLM

The candidate is trained on `with_time_split` (`data/time_split.py`) as the deployed bundle is on `with_normalized`:
both stages, reader 2, the cutoffs and DistilBERT's threshold chosen on its validation emails. It is never deployed.
It runs as the service runs a bundle, one email at a time, on the phishing before and after the cut, each month
after it, and the clean tests every model is measured on, so a change in false alarms shows too. The deployed bundle
is run on the same emails for comparison, but it trained on some of the after-cut phishing, so its after-cut row
counts only the emails it never saw. The private tests are scored on this laptop and only their counts are written.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPORTS_DIR = Path("reports")
NAME = "time_split"
DISTILBERT = Path("artifacts/distilbert_with_time_split")


def build() -> str:
    from phish_triage.data import time_split
    from phish_triage.service.bundle import CANDIDATE_ROOT, export_candidate

    if not (DISTILBERT / "model.onnx").exists():
        raise SystemExit(f"{DISTILBERT}/model.onnx is missing (make train-time-split)")
    if built := [p.name for p in (CANDIDATE_ROOT / NAME).glob("*") if p.is_dir()]:
        return built[0]
    return export_candidate(time_split.SPLIT, DISTILBERT, NAME, reader=2).name


def measure() -> dict:
    from phish_triage.data import inbox, time_split
    from phish_triage.data.build import INTERIM_DIR
    from phish_triage.evaluation.defence import test_sets
    from phish_triage.service.bundle import CANDIDATE_ROOT, DEPLOYED_SPLIT, latest, load_split
    from phish_triage.service.scanner import Scanner

    clean, records = test_sets()
    deployed_split, deployed_slices = load_split(DEPLOYED_SPLIT)
    _, slices = time_split.load()
    records |= inbox.read_split_records(set(slices["phish_after_cut"]) - set(records))
    month = {e["id"]: (e["date"] or "")[:7] for e in json.loads((INTERIM_DIR / "index.json").read_text())}
    seen = set(deployed_split["train"]) | set(deployed_split["val"])
    after = slices["phish_after_cut"]
    sets = {
        "phish_before_cut": slices["phish_before_cut"],
        "phish_after_cut": after,
        **{f"month_{m}": [i for i in after if month.get(i) == m] for m in sorted({month.get(i) for i in after})},
        "public_phish": clean["public_phish"],
        "public_legit": clean["public_legit"],
        "inbox_test": clean["inbox_test"],
        "privacymail_test": clean["privacymail_test"],
    }
    (candidate,) = [p for p in (CANDIDATE_ROOT / NAME).iterdir() if p.is_dir()]
    out: dict = {"cut": time_split.CUT, "bundles": {}, "candidate": {}, "deployed": {}}
    for who, folder in (("candidate", candidate), ("deployed", latest(split=DEPLOYED_SPLIT))):
        scanner = Scanner(folder, threads=4)
        out["bundles"][who] = scanner.version
        for name, ids in sets.items():
            if who == "deployed" and (name == "phish_after_cut" or name.startswith("month_")):
                ids = [i for i in ids if i not in seen]  # only the ones it never trained on
            results = [scanner.scan_record(records[i]) for i in ids]
            out[who][name] = {
                "emails": len(ids),
                "flagged": sum(r.cascade_phish for r in results),
                "stage1_decided": sum(r.stage == "stacked" for r in results),
            }
            print(f"{who} {name}: {out[who][name]}", file=sys.stderr)
    out["deployed_2026_test_after_cut"] = len(set(deployed_slices["phish_2026_test"]) & set(after))
    return out


# --- The report ---

ROWS = {
    "phish_before_cut": "2026 phishing before the cut, caught",
    "phish_after_cut": "Phishing after the cut, caught",
    "public_phish": "Public test, phishing caught",
    "public_legit": "Public test, legitimate flagged",
    "inbox_test": "My inbox's test senders flagged",
    "privacymail_test": "PrivacyMail held-out websites flagged",
}


STAGE1_ROWS = {
    "phish_before_cut": "2026 phishing before the cut",
    "phish_after_cut": "Phishing after the cut",
    "public_phish": "Public test, phishing",
    "public_legit": "Public test, legitimate",
    "inbox_test": "My inbox's test senders",
    "privacymail_test": "PrivacyMail held-out websites",
}


def _stage1(v: dict) -> str:
    return f"{v['stage1_decided'] / v['emails']:.0%}" if v["emails"] else "—"


def _cell(v: dict) -> str:
    return f"{v['flagged'] / v['emails']:.1%} ({v['flagged']:,} of {v['emails']:,})" if v["emails"] else "—"


def to_markdown(r: dict) -> str:
    months = [k for k in r["candidate"] if k.startswith("month_")]
    lines = [
        "# Phishing from months after training",
        "",
        "Generated by `make time-split`. The candidate is trained as the deployed bundle is, but on the split "
        f"`with_time_split`: every phishing email dated {r['cut']} or later is taken out of training and validation, "
        "so it has seen phishing only up to the month before. The legitimate mail is unchanged. It is never deployed. "
        f"*Deployed* is `{r['bundles']['deployed']}`; it trained on phishing from every month up to October 2026, so "
        "its after-cut rows count only the emails it never saw. The private tests are scored on my laptop; only "
        "counts are shown.",
        "",
        f"| | Candidate (`{r['bundles']['candidate']}`) | Deployed |",
        "|---|---:|---:|",
        *[f"| {label} | {_cell(r['candidate'][k])} | {_cell(r['deployed'][k])} |" for k, label in ROWS.items()],
        "",
        "## After the cut, by month",
        "",
        "| Month | Candidate | Deployed |",
        "|---|---:|---:|",
        *[f"| {m.removeprefix('month_')} | {_cell(r['candidate'][m])} | {_cell(r['deployed'][m])} |" for m in months],
        "",
        "## Decided by stage 1",
        "",
        "| | Candidate | Deployed |",
        "|---|---:|---:|",
        *[
            f"| {label} | " + " | ".join(_stage1(r[w][k]) for w in ("candidate", "deployed")) + " |"
            for k, label in STAGE1_ROWS.items()
        ],
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("build", "measure", "report"))
    args = parser.parse_args(argv)
    path = REPORTS_DIR / "time_split.json"
    if args.command == "build":
        print(build())
        return 0
    if args.command == "measure":
        path.write_text(json.dumps(measure(), indent=1) + "\n")
    text = to_markdown(json.loads(path.read_text()))
    (REPORTS_DIR / "time_split.md").write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
