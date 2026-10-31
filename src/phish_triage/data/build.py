"""Parse every downloaded source into one file of unified records, and summarize what came out.

    python -m phish_triage.data.build                  # all sources
    python -m phish_triage.data.build nazario apache   # some sources

Writes data/interim/records.jsonl.gz (one EmailRecord per line) and data/interim/summary.json.
Only counts are printed, never email content.
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

from phish_triage.data.download import RAW_DIR
from phish_triage.data.loaders import iter_source
from phish_triage.data.parse import parse_email
from phish_triage.data.sources import SOURCES

INTERIM_DIR = Path("data/interim")


def build(names: list[str], raw_dir: Path = RAW_DIR, out_dir: Path = INTERIM_DIR) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    counts: Counter[tuple[str, str]] = Counter()
    years: defaultdict[str, Counter[str]] = defaultdict(Counter)
    date_from: defaultdict[str, Counter[str]] = defaultdict(Counter)
    with_errors: Counter[str] = Counter()
    with gzip.open(out_dir / "records.jsonl.gz", "wt", encoding="utf-8") as out:
        for name in names:
            for raw, label, origin in iter_source(SOURCES[name], raw_dir):
                record = parse_email(raw, source=name, label=label, origin=origin)
                out.write(json.dumps(record.to_dict(), ensure_ascii=False) + "\n")
                counts[name, label] += 1
                years[f"{name}/{label}"][record.date[:4] if record.date else "unknown"] += 1
                date_from[name][record.date_from] += 1
                with_errors[name] += bool(record.parse_errors)
            print(f"{name}: {sum(c for (s, _), c in counts.items() if s == name)} messages", file=sys.stderr)
    summary = {
        "messages": {f"{s}/{label}": c for (s, label), c in sorted(counts.items())},
        "by_year": {k: dict(sorted(v.items())) for k, v in sorted(years.items())},
        "date_from": {k: dict(v) for k, v in sorted(date_from.items())},
        "messages_with_parse_errors": dict(with_errors),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("sources", nargs="*", help=f"any of: {', '.join(SOURCES)} (default: all)")
    args = parser.parse_args(argv)
    if unknown := set(args.sources) - set(SOURCES):
        parser.error(f"unknown source(s): {', '.join(sorted(unknown))}")
    summary = build(args.sources or list(SOURCES))
    print(json.dumps(summary["messages"], indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
