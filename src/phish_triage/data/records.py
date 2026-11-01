"""Read unified records (raw or masked) by id from the JSON-lines files the data pipeline writes."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

from phish_triage.data.build import INTERIM_DIR

RAW_RECORDS = INTERIM_DIR / "records.jsonl.gz"
MASKED_RECORDS = INTERIM_DIR / "masked.jsonl.gz"


def read_records(path: Path, ids: set[str]) -> dict[str, dict]:
    """Records whose id is in `ids`. The id is the first field, so other lines are skipped without parsing."""
    found = {}
    with gzip.open(path, "rt", encoding="utf-8") as lines:
        for line in lines:
            if line[8:24] in ids and line[8:24] not in found:
                record = json.loads(line)
                found[record["id"]] = record
    return found
