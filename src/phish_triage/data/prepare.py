"""Mask source fingerprints and remove duplicates: data/interim/records.jsonl.gz -> masked records + duplicate list.

    python -m phish_triage.data.prepare

Writes:
- data/interim/masked.jsonl.gz: every unique email, masked (`mask.py`); byte-identical copies are written once;
- data/interim/dedup.json: which emails are duplicates of which, label conflicts, and counts per source;
- data/interim/index.json: id, source, label, date and whether it survived duplicate removal, for `splits.py`.

Masking runs first so that duplicates are found on the masked text: an announcement cross-posted to two Apache
lists differs only in its list footer and subject tag, and should count as one email.
Only counts are printed, never email content.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import sys
from collections import Counter, defaultdict
from multiprocessing import Pool
from pathlib import Path

from phish_triage.data import dedup
from phish_triage.data.build import INTERIM_DIR
from phish_triage.data.mask import mask_record

_PERMUTATIONS = None


def _init_worker() -> None:
    global _PERMUTATIONS
    _PERMUTATIONS = dedup.permutations()


def _process(line: str) -> tuple[str, dedup.Item]:
    masked = mask_record(json.loads(line))
    return json.dumps(masked, ensure_ascii=False), dedup.make_item(masked, _PERMUTATIONS)


def prepare(in_dir: Path = INTERIM_DIR, out_dir: Path = INTERIM_DIR, workers: int | None = None) -> dict:
    workers = workers or max(1, (os.cpu_count() or 2) - 1)
    items: list[dedup.Item] = []
    seen: set[str] = set()
    identical: defaultdict[str, Counter] = defaultdict(Counter)
    tmp = out_dir / "masked.jsonl.gz.part"
    with (
        gzip.open(in_dir / "records.jsonl.gz", "rt", encoding="utf-8") as records,
        gzip.open(tmp, "wt", encoding="utf-8") as out,
        Pool(workers, initializer=_init_worker) as pool,
    ):
        for masked_line, item in pool.imap(_process, records, chunksize=64):
            if item.id in seen:
                identical[f"{item.source}/{item.label}"]["before"] += 1
                identical[f"{item.source}/{item.label}"]["identical_file"] += 1
                continue
            seen.add(item.id)
            items.append(item)
            out.write(masked_line + "\n")
            if len(items) % 20_000 == 0:
                print(f"masked {len(items)} emails", file=sys.stderr)
    tmp.replace(out_dir / "masked.jsonl.gz")

    print(f"finding duplicates among {len(items)} unique emails", file=sys.stderr)
    result = dedup.find_duplicates(items)
    report = result.report
    for key, counts in identical.items():
        merged = Counter(report["per_source"].get(key, {}))
        merged.update(counts)
        report["per_source"][key] = dict(merged)
    report["totals"] = {
        "before": sum(c.get("before", 0) for c in report["per_source"].values()),
        "kept": len(result.keep),
        "label_conflicts": len(result.conflicts),
        "empty": len(result.empty),
    }
    (out_dir / "dedup.json").write_text(
        json.dumps(
            {
                "report": report,
                "conflicts": sorted(result.conflicts),
                "duplicate_of": dict(sorted(result.duplicate_of.items())),
            },
            indent=1,
        )
        + "\n"
    )
    index = [
        {"id": i.id, "source": i.source, "label": i.label, "date": i.date or None, "kept": i.id in result.keep}
        for i in items
    ]
    (out_dir / "index.json").write_text(json.dumps(index) + "\n")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--workers", type=int, default=None, help="parallel processes (default: CPUs - 1)")
    args = parser.parse_args(argv)
    report = prepare(workers=args.workers)
    print(json.dumps(report["totals"], indent=1))
    for key, counts in report["per_source"].items():
        print(f"  {key}: {counts.get('before', 0)} -> {counts.get('kept', 0)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
