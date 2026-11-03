"""My private test inbox: read the Takeout export and build the `with_inbox` split from it.

    python -m phish_triage.data.inbox    # or `make data-inbox`

The inbox is a fresh Gmail account I subscribed to newsletters, shops and services, exported with Google Takeout
to data/private/test_inbox/test_inbox.mbox. Everything derived from it stays in that folder (ignored by git):
the masked records and the split. Only counts are printed. It is never sent to an LLM (the analyst and the Claude
classifier refuse `test_inbox` records in code).

**Why a split with it.** Trained only on public data, the models flag 96–99.6% of this inbox as phishing
(reports/test_inbox.md): the only legitimate training mail is plain-text mailing-list discussion. `with_inbox`
adds part of the inbox to the `random` split:

- **By sender.** Sender domains (the registered domain of From) go to train, val or test in a fixed pattern over
  the domains sorted by size (train, val, test, train, train), so about 60/20/20 of the domains and the largest
  senders are spread over all three. Test senders are never seen in training.
- **At most 25 emails per sender in train and val,** so the model learns newsletters, not one company's template.
  Test keeps every email of its senders.
- **2026 phishing to match.** The inbox is late 2026, while most 2026 phishing was left out of the month-matched
  pool. Without it, "2026" or "November" would be a legitimate-only word. The left-out 2026 phishing_pot emails
  are shuffled and added to train and val in the same numbers as the inbox emails there; the rest is a test set
  of 2026 phishing.
- The Spam folder is never used for training; it is reported as a share flagged.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

from phish_triage.data.build import INTERIM_DIR
from phish_triage.data.loaders import _iter_mbox
from phish_triage.data.mask import mask_record
from phish_triage.data.parse import parse_email
from phish_triage.data.records import MASKED_RECORDS, read_records
from phish_triage.data.splits import SEED, SPLITS_DIR

PRIVATE_DIR = Path("data/private/test_inbox")
MBOX = PRIVATE_DIR / "test_inbox.mbox"
INBOX_MASKED = PRIVATE_DIR / "masked.jsonl.gz"
SPLIT_FILE = PRIVATE_DIR / "split.json"
SOURCE = "test_inbox"
SPLIT = "with_inbox"
BASE_SPLIT = "random"
PER_SENDER_CAP = 25
DOMAIN_PATTERN = ("train", "val", "test", "train", "train")
PHISH_2026 = ("phishing_pot", "2026-01")  # source, first month

# Most specific first. "Category Personal" is Gmail's Primary tab; an email in the inbox with no category is too.
CATEGORIES = (
    ("Spam", "spam"),
    ("Category Purchases", "purchases"),
    ("Category Promotions", "promotions"),
    ("Category Social", "social"),
    ("Category Forums", "forums"),
    ("Category Updates", "updates"),
    ("Category Personal", "primary"),
)
SKIPPED_LABELS = {"Sent", "Drafts", "Chat"}  # my own messages, not mail I received


def gmail_category(labels_header: str | None) -> str | None:
    """One category per email from Takeout's X-Gmail-Labels header; None for messages I sent."""
    labels = {label.strip() for label in (labels_header or "").split(",") if label.strip()}
    if labels & SKIPPED_LABELS:
        return None
    for label, category in CATEGORIES:
        if label in labels:
            return category
    return "primary" if "Inbox" in labels else "other"


def load_inbox(path: Path = MBOX) -> tuple[list[dict], list[str], int]:
    """(parsed records, their categories, messages skipped). Nothing is printed or written here."""
    records, categories, skipped = [], [], 0
    for raw, origin in _iter_mbox(path, "mbox"):
        header_end = raw.find(b"\n\n")
        head = raw[: header_end if header_end >= 0 else len(raw)]
        labels = next(
            (
                line.split(b":", 1)[1].decode("utf-8", "replace")
                for line in head.splitlines()
                if line.lower().startswith(b"x-gmail-labels:")
            ),
            None,
        )
        category = gmail_category(labels)
        if category is None:
            skipped += 1
            continue
        label = "spam" if category == "spam" else "legit"
        record = parse_email(raw, source=SOURCE, label=label, origin=f"test_inbox.mbox{origin}").to_dict()
        records.append(record | {"category": category})
        categories.append(category)
    return records, categories, skipped


def sender_group(record: dict) -> str:
    """The sender's registered domain, hashed: the split only needs to know which emails share a sender."""
    from phish_triage.features.domains import registered_domain
    from phish_triage.features.sender import identity

    domain = registered_domain(identity(record["headers"]).domain or "") or ""
    return hashlib.sha256(domain.encode()).hexdigest()[:12]


def assign_senders(groups: dict[str, int], pattern: tuple[str, ...] = DOMAIN_PATTERN) -> dict[str, str]:
    """Sender -> part, cycling `pattern` over the senders sorted by size (ties by group id, so it's stable)."""
    order = sorted(groups, key=lambda g: (-groups[g], g))
    return {g: pattern[k % len(pattern)] for k, g in enumerate(order)}


def build_split(
    inbox: list[dict], base: dict[str, list[str]], phish_2026: list[str], seed: int = SEED
) -> tuple[dict[str, list[str]], dict]:
    """(`with_inbox` train/val/test ids, the named test slices and sender groups)."""
    rng = random.Random(f"{seed}-with-inbox")
    legit = [r for r in inbox if r["label"] == "legit"]
    group = {r["id"]: sender_group(r) for r in inbox}
    by_group: defaultdict[str, list[str]] = defaultdict(list)
    for r in legit:
        by_group[group[r["id"]]].append(r["id"])
    part_of = assign_senders({g: len(ids) for g, ids in by_group.items()})
    inbox_parts: dict[str, list[str]] = {"train": [], "val": [], "test": []}
    for g in sorted(by_group):
        ids = sorted(by_group[g])
        if part_of[g] != "test" and len(ids) > PER_SENDER_CAP:
            ids = sorted(rng.sample(ids, PER_SENDER_CAP))
        inbox_parts[part_of[g]] += ids
    phish = sorted(phish_2026)
    rng.shuffle(phish)
    n_train, n_val = len(inbox_parts["train"]), len(inbox_parts["val"])
    phish_parts = {"train": phish[:n_train], "val": phish[n_train : n_train + n_val], "test": phish[n_train + n_val :]}
    split = {part: base[part] + inbox_parts[part] + phish_parts[part] for part in ("train", "val", "test")}
    slices = {
        "public_test": base["test"],
        "inbox_test": inbox_parts["test"],
        "phish_2026_test": phish_parts["test"],
        "spam_folder": sorted(r["id"] for r in inbox if r["label"] == "spam"),
        "sender_group": {i: group[i] for i in inbox_parts["test"]},
        "category": {r["id"]: r["category"] for r in inbox},
    }
    return split, slices


def left_out_2026_phishing(splits: dict) -> list[str]:
    used = {i for name in splits.values() for part in name.values() for i in part}
    index = json.loads((INTERIM_DIR / "index.json").read_text())
    source, first = PHISH_2026
    return [
        e["id"]
        for e in index
        if e["kept"]
        and e["label"] == "phish"
        and e["source"] == source
        and (e["date"] or "")[:7] >= first
        and e["id"] not in used
    ]


def write_masked(records: list[dict], path: Path = INBOX_MASKED) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as out:
        for record in records:
            out.write(json.dumps(mask_record(record), ensure_ascii=False) + "\n")


def read_split_records(ids: set[str]) -> dict[str, dict]:
    """Records from the public masked file and, for `with_inbox`, the private one."""
    found = read_records(MASKED_RECORDS, ids)
    if INBOX_MASKED.exists() and ids - found.keys():
        found |= read_records(INBOX_MASKED, ids - found.keys())
    return found


def load_split() -> tuple[dict[str, list[str]], dict]:
    saved = json.loads(SPLIT_FILE.read_text())
    return saved[SPLIT], saved["slices"]


def main(argv: list[str] | None = None) -> int:
    if not MBOX.exists():
        raise SystemExit(f"{MBOX} is missing (see the module docstring)")
    records, categories, skipped = load_inbox()
    write_masked(records)
    splits = json.loads((SPLITS_DIR / "splits.json").read_text())
    phish = left_out_2026_phishing(splits)
    split, slices = build_split(records, splits[BASE_SPLIT], phish)
    SPLIT_FILE.write_text(json.dumps({SPLIT: split, "slices": slices}) + "\n")
    labels = {r["id"]: r["label"] for r in records}
    counts = {
        part: Counter("inbox" if i in labels else "public or 2026 phishing" for i in ids) for part, ids in split.items()
    }
    print(f"{len(records)} inbox emails ({skipped} sent by me left out), {Counter(categories)}", file=sys.stderr)
    print(f"2026 phishing left out of the pool: {len(phish)}", file=sys.stderr)
    for part, c in counts.items():
        print(f"{part}: {len(split[part])} ({dict(c)})", file=sys.stderr)
    print(
        f"inbox test: {len(slices['inbox_test'])} emails from {len(set(slices['sender_group'].values()))} senders; "
        f"2026 phishing test: {len(slices['phish_2026_test'])}; spam folder: {len(slices['spam_folder'])}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
