"""Find exact and near-duplicate emails, within and across sources, and keep one email per group.

Phishing campaigns send the same message thousands of times with a different tracking link or name, and mailing
lists cross-post one announcement to several lists. If copies of one email land in both the training and the test
set, the test measures memory, not detection.

- **Exact:** same subject and body after lowercasing and replacing numbers, links and addresses with placeholders.
  When the plain text is short (often just "your client can't display this message"), the visible text of the
  HTML part is added, and the attachment types become part of the key.
- **Near:** MinHash LSH on word 5-grams of that same text, at Jaccard similarity >= `THRESHOLD`. Groups are
  joined transitively (A~B and B~C puts all three in one group).

Each group keeps its earliest email (ties broken by id). A group that mixes labels (a "phishing" email that is a
copy of a "legitimate" one) is ambiguous, so all of its emails are dropped and counted as label conflicts.
Emails with no subject, no body text and no attachment are dropped as empty: there is nothing to compare or learn.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from dataclasses import dataclass

import numpy as np
from datasketch import MinHash, MinHashLSH

from phish_triage.data.parse import html_to_text

THRESHOLD = 0.9
NUM_PERM = 128
SHINGLE = 5
MIN_TOKENS = 20  # shorter texts have too few shingles for a reliable estimate; they get exact matching only
MAX_TOKENS = 3000  # long quoted threads: the first 3,000 words are enough to recognise a copy
SCHEME = "affine32"
# 16 bands of 8 rows: a pair at similarity 0.9 becomes a candidate with probability ~1.0 (0.8: 0.95, 0.5: 0.06).
# datasketch's default for threshold 0.9 finds only ~31% of pairs at 0.9. Every candidate is then checked against
# THRESHOLD on its estimated similarity, so the wider net costs time, not precision.
LSH_BANDS = (16, 8)

_URL_RE = re.compile(r"(?:https?://|www\.)\S+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_NUMBER_RE = re.compile(r"\d+")
_TOKEN_RE = re.compile(r"\w+")


@dataclass
class Item:
    id: str
    source: str
    label: str
    date: str  # ISO date, or "" when unknown (a dated copy is kept in preference)
    exact_key: str
    hashvalues: np.ndarray | None  # MinHash signature, or None for short texts
    empty: bool = False


@dataclass
class Result:
    keep: set[str]
    duplicate_of: dict[str, str]  # removed id -> the id kept for its group
    conflicts: set[str]  # ids dropped because their group mixed labels
    empty: set[str]  # ids dropped because they have no text and no attachment
    report: dict


def tokens(subject: str, text: str) -> list[str]:
    combined = f"{subject}\n{text}".lower()
    combined = _URL_RE.sub(" url ", combined)
    combined = _EMAIL_RE.sub(" email ", combined)
    combined = _NUMBER_RE.sub(" 0 ", combined)
    return _TOKEN_RE.findall(combined)


def make_item(record: dict, permutations: np.ndarray) -> Item:
    subject, text, attachments = record["subject"] or "", record["text"] or "", record.get("attachments") or []
    words = tokens(subject, text)
    if len(words) < MIN_TOKENS and record.get("html"):
        words = tokens(subject, f"{text}\n{html_to_text(record['html'])}")
    key = " ".join(words)
    if len(words) < MIN_TOKENS:
        key += "\n" + " ".join(sorted(a["content_type"] for a in attachments))
    exact_key = hashlib.sha256(key.encode()).hexdigest()[:20]
    hashvalues = None
    if len(words) >= MIN_TOKENS:
        words = words[:MAX_TOKENS]
        shingles = {" ".join(words[i : i + SHINGLE]).encode() for i in range(len(words) - SHINGLE + 1)}
        minhash = MinHash(num_perm=NUM_PERM, permutations=permutations, scheme=SCHEME)
        minhash.update_batch(shingles)
        hashvalues = minhash.hashvalues.copy()
    empty = not words and not attachments
    return Item(record["id"], record["source"], record["label"], record["date"] or "", exact_key, hashvalues, empty)


def permutations() -> np.ndarray:
    return MinHash(num_perm=NUM_PERM, scheme=SCHEME).permutations


def find_duplicates(items: list[Item], threshold: float = THRESHOLD) -> Result:
    """Group duplicates. Ids must be unique: byte-identical files are removed before this step."""
    assert len({item.id for item in items}) == len(items), "ids must be unique"
    empty = {item.id for item in items if item.empty}
    all_items, items = items, [item for item in items if not item.empty]
    parent = list(range(len(items)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[max(ri, rj)] = min(ri, rj)

    exact_first: dict[str, int] = {}
    exact_pairs = 0
    for i, item in enumerate(items):
        if item.exact_key in exact_first:
            union(exact_first[item.exact_key], i)
            exact_pairs += 1
        else:
            exact_first[item.exact_key] = i

    # Near-duplicates: one representative per exact group is enough.
    lsh = MinHashLSH(num_perm=NUM_PERM, params=LSH_BANDS)
    signatures: dict[int, MinHash] = {}
    for i in exact_first.values():
        if items[i].hashvalues is not None:
            signatures[i] = MinHash(num_perm=NUM_PERM, hashvalues=items[i].hashvalues, scheme=SCHEME)
            lsh.insert(i, signatures[i])
    for i, signature in signatures.items():
        for j in lsh.query(signature):
            if j > i and signature.jaccard(signatures[j]) >= threshold:
                union(i, j)

    groups: defaultdict[int, list[int]] = defaultdict(list)
    for i in range(len(items)):
        groups[find(i)].append(i)

    keep: set[str] = set()
    duplicate_of: dict[str, str] = {}
    conflicts: set[str] = set()
    for members in groups.values():
        if len({items[i].label for i in members}) > 1:
            conflicts.update(items[i].id for i in members)
            continue
        kept = min(members, key=lambda i: (items[i].date or "9999", items[i].id))
        keep.add(items[kept].id)
        for i in members:
            if i != kept:
                duplicate_of[items[i].id] = items[kept].id

    return Result(keep, duplicate_of, conflicts, empty, _report(all_items, keep, duplicate_of, conflicts, empty))


def _report(items: list[Item], keep, duplicate_of, conflicts, empty) -> dict:
    by_id = {item.id: item for item in items}
    per_source: defaultdict[str, Counter] = defaultdict(Counter)
    for item in items:
        counts = per_source[f"{item.source}/{item.label}"]
        counts["before"] += 1
        if item.id in keep:
            counts["kept"] += 1
        elif item.id in conflicts:
            counts["label_conflict"] += 1
        elif item.id in empty:
            counts["empty"] += 1
        else:
            kept = by_id[duplicate_of[item.id]]
            kind = "exact" if kept.exact_key == item.exact_key else "near"
            where = "same_source" if kept.source == item.source else "other_source"
            counts[f"{kind}_{where}"] += 1
        counts["short_text"] += item.hashvalues is None
    return {
        "threshold": THRESHOLD,
        "lsh_bands": list(LSH_BANDS),
        "num_perm": NUM_PERM,
        "shingle_words": SHINGLE,
        "per_source": {k: dict(v) for k, v in sorted(per_source.items())},
    }
