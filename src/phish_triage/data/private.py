"""The emails that never reach an LLM: my test inbox, PrivacyMail, and the emails I send for retraining.

Every path that sends an email to Claude (`service/analyst.py`, `models/llm_classifier.py`) calls `refuse_private`
first. It refuses a record by its `source` label and, because a label is only as good as the code path that set it,
also by its id: the ids of every record in the private masked files. On the deployed service those files don't
exist, and the emails are my own, scanned at my request through the add-on.
"""

from __future__ import annotations

import gzip
import json
from functools import lru_cache
from pathlib import Path

PRIVATE_SOURCES = frozenset({"test_inbox", "privacymail", "private", "retraining"})
PRIVATE_FILES = (
    Path("data/private/test_inbox/masked.jsonl.gz"),
    Path("data/private/privacymail/masked.jsonl.gz"),
)
REFUSAL = "private emails (my test inbox, PrivacyMail) are never sent to an LLM"


@lru_cache(maxsize=1)
def private_ids() -> frozenset[str]:
    ids = set()
    for path in PRIVATE_FILES:
        if path.exists():
            with gzip.open(path, "rt", encoding="utf-8") as f:
                ids.update(json.loads(line)["id"] for line in f if line.strip())
    return frozenset(ids)


def refuse_private(record: dict) -> None:
    if record.get("source") in PRIVATE_SOURCES or record.get("id") in private_ids():
        raise PermissionError(REFUSAL)
