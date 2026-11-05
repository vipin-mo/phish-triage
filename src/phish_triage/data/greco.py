"""Greco et al.'s LLM-written emails (Kaggle, version 1), read straight from the zip: a robustness test only.

Only the two `llm-generated/` files are used: 1,000 phishing and 1,000 "legitimate" emails written by an LLM. The
`human-generated/` half overlaps my training data (854 of its 1,000 phishing emails went to `jose@monkey.org`, Nazario's
corpus, and its legitimate mail is from CEAS 2008, SpamAssassin and openSUSE lists), so it would not be a test.

Each email is the body text alone (with its links written into the text): no sender or subject. So each becomes the
same plain-text message with a made-up sender and recipient and an empty subject, and only the text differs between
the two files. The phishing file isn't quoted, so a row's commas split its text into columns; they are joined back.

The `legit.csv` file is not usable as legitimate mail: its `label` column says 1 (phishing, as in the human files) on
every row, and 316 of its 1,000 emails ask the reader to verify an account or claim something at a made-up link,
like the phishing. Its records keep the file name's label, but the robustness report shows only how much of it is
flagged and makes no false-alarm claim from it. Two emails appear twice; the second copy is dropped.
"""

from __future__ import annotations

import csv
import io
import sys
import zipfile
from pathlib import Path

from phish_triage.data.download import RAW_DIR
from phish_triage.data.sources import ROBUSTNESS

ZIP_PATH = RAW_DIR / "greco" / ROBUSTNESS["greco"].files[0].filename
SOURCE = "greco"
FILES = {"llm-generated/phishing.csv": "phish", "llm-generated/legit.csv": "legit"}
HEADERS = (
    "From: sender@example.com\nTo: user@example.com\nSubject: \nMIME-Version: 1.0\n"
    "Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\n"
)


def llm_written(path: Path = ZIP_PATH) -> list[tuple[str, str, str]]:
    """(label, origin, text) for each LLM-written email, in file order."""
    csv.field_size_limit(sys.maxsize)
    rows = []
    with zipfile.ZipFile(path) as z:
        for name, label in FILES.items():
            reader = csv.reader(io.TextIOWrapper(z.open(name), encoding="utf-8", errors="replace"))
            header = next(reader)
            if header != ["text", "label"]:
                raise ValueError(f"{name}: unexpected columns {header}")
            for n, row in enumerate(reader):
                rows.append((label, f"{name}:{n + 2}", ",".join(row[:-1]).strip()))
    return rows


def records(path: Path = ZIP_PATH) -> list[dict]:
    """The LLM-written emails as masked records, as the service would see them."""
    from phish_triage.data.mask import mask_record
    from phish_triage.data.parse import parse_email

    out, seen = [], set()
    for label, origin, text in llm_written(path):
        raw = (HEADERS + text + "\n").encode("utf-8")
        record = mask_record(parse_email(raw, source=SOURCE, label=label, origin=origin).to_dict())
        if record["id"] not in seen:
            seen.add(record["id"])
            out.append(record)
    return out
