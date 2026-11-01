"""Read my course project's dataset (Kaggle, version 1) straight from its zip file, without unpacking it.

- `combined()`: `phishing_email.csv`, the exact file the course trained on (82,486 rows of cleaned text).
- `by_source()`: the six CSVs it was built from (CEAS-08, Enron, Ling, Nazario, Nigerian fraud, SpamAssassin),
  as subject + body with the source name. The combined file is not a plain concatenation of them (four sources
  were cleaned differently), so source-level tests use these.

Label 1 is "phishing" in the course's sense: in four of the six sources it means spam.
"""

from __future__ import annotations

import csv
import io
import sys
import zipfile
from collections.abc import Iterator
from pathlib import Path

from phish_triage.data.download import RAW_DIR
from phish_triage.data.sources import COURSE

ZIP_PATH = RAW_DIR / "course" / COURSE["course"].files[0].filename
COMBINED = "phishing_email.csv"
SOURCE_FILES = {
    "CEAS_08.csv": "ceas",
    "Enron.csv": "enron",
    "Ling.csv": "ling",
    "Nazario.csv": "nazario",
    "Nigerian_Fraud.csv": "nigerian",
    "SpamAssasin.csv": "spamassassin",
}


def _rows(name: str, path: Path) -> Iterator[dict]:
    csv.field_size_limit(sys.maxsize)
    if not path.exists():
        raise FileNotFoundError(f"{path} is missing; run `make data-download` (needs a Kaggle token)")
    with zipfile.ZipFile(path) as archive, archive.open(name) as f:
        yield from csv.DictReader(io.TextIOWrapper(f, encoding="utf-8", errors="replace"))


def combined(path: Path = ZIP_PATH) -> tuple[list[str], list[int]]:
    texts, labels = [], []
    for row in _rows(COMBINED, path):
        texts.append(row["text_combined"] or "")
        labels.append(int(row["label"]))
    return texts, labels


def by_source(path: Path = ZIP_PATH) -> tuple[list[str], list[int], list[str]]:
    texts, labels, sources = [], [], []
    for name, source in SOURCE_FILES.items():
        for row in _rows(name, path):
            texts.append(f"{row.get('subject') or ''}\n{row.get('body') or ''}")
            labels.append(int(row["label"]))
            sources.append(source)
    return texts, labels, sources
