"""The emails I sent for retraining, and the `with_retraining` split built from them.

    python -m phish_triage.data.retraining --pull     # or `make retrain-pull` (needs the MFA session)
    python -m phish_triage.data.retraining --build    # the split

**Pull.** Each email in the retraining bucket (`service/retraining.py`; what the add-on's "Send as phishing /
legitimate" stored) is parsed with the source `retraining` and the label I gave, masked like the training data, added
to data/private/retraining/masked.jsonl.gz (never committed, never sent to an LLM: `data/private.py`) and then deleted
from the bucket: "deleted once used". Duplicates of an email already pulled are skipped. Only counts are printed.

**Split.** `with_retraining` is the deployed `with_newsletters` split with every pulled email added to training only:
there are too few to test on, and the validation and test parts stay exactly as they were, so the retrained model is
measured on the same emails as the one it would replace (reports/with_inbox.md, the *retrained* setup). Only stage 1,
the stacked model, is retrained; DistilBERT is reused as it is (`evaluation/with_inbox.DISTILBERT_FROM`).
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
from pathlib import Path

PRIVATE_DIR = Path("data/private/retraining")
MASKED = PRIVATE_DIR / "masked.jsonl.gz"
SPLIT_FILE = PRIVATE_DIR / "split.json"
SOURCE = "retraining"
SPLIT = "with_retraining"
# The same emails read with reader 2 (Phase 7.2): what the models train on changes, the split doesn't.
NORMALIZED_SPLIT = "with_normalized"
LABEL_OF = {"phish": "phish", "legit": "legit"}
# Whose emails may be sent for retraining: the service refuses every other key, and `--pull` takes only these.
# One owner per line; Terraform reads the same file (infra/service).
OWNERS_FILE = Path("infra/retraining-owners")


def owners() -> tuple[str, ...]:
    return tuple(line.strip() for line in OWNERS_FILE.read_text().splitlines() if line.strip())


def read_masked() -> dict[str, dict]:
    if not MASKED.exists():
        return {}
    with gzip.open(MASKED, "rt", encoding="utf-8") as f:
        return {(r := json.loads(line))["id"]: r for line in f if line.strip()}


def pull(bucket: str, s3=None, allowed: tuple[str, ...] | None = None) -> dict:
    """Move the sent emails of the allowed owners (`infra/retraining-owners`) from the bucket into the private masked
    file; anyone else's are left where they are and only counted. Returns counts only."""
    from phish_triage.data.mask import mask_record
    from phish_triage.data.parse import parse_email

    if s3 is None:
        import boto3

        s3 = boto3.client("s3")
    kept = read_masked()
    counts = {"in bucket": 0, "added": 0, "already pulled": 0, "phish": 0, "legit": 0}
    allowed = owners() if allowed is None else allowed
    pages = s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="emails/")
    every = [o["Key"] for page in pages for o in page.get("Contents", [])]
    keys = [k for k in every if k.split("/")[1] in allowed]
    counts["other owners' emails, left in the bucket"] = len(every) - len(keys)
    new = []
    for key in keys:
        counts["in bucket"] += 1
        obj = s3.get_object(Bucket=bucket, Key=key)
        label = LABEL_OF[obj["Metadata"]["label"]]
        record = parse_email(obj["Body"].read(), source=SOURCE, label=label, origin="retraining").to_dict()
        masked = mask_record(record)
        if masked["id"] in kept:
            counts["already pulled"] += 1
        else:
            kept[masked["id"]] = masked
            new.append(masked["id"])
            counts["added"] += 1
            counts[label] += 1
    PRIVATE_DIR.mkdir(parents=True, exist_ok=True)
    with gzip.open(MASKED, "wt", encoding="utf-8") as f:
        for r in kept.values():
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    for key in keys:  # only after they are safely saved
        s3.delete_object(Bucket=bucket, Key=key)
    counts["deleted from bucket"] = len(keys)
    counts["total pulled"] = len(kept)
    return counts


def build_split(
    base: dict[str, list[str]], retraining_ids: list[str], left_out: set[str] = frozenset()
) -> dict[str, list[str]]:
    seen = set(base["train"]) | set(base["val"]) | set(base["test"])
    added = [i for i in sorted(retraining_ids) if i not in seen and i not in left_out]
    return {"train": base["train"] + added, "val": list(base["val"]), "test": list(base["test"])}


def like_a_test_email(records: dict[str, dict], tests: list[dict]) -> set[str]:
    """The sent emails that share a sender domain with a test email, or copy one (exactly, or at the de-duplication's
    near-copy similarity): training on them would leak into those tests, which keep senders apart for this reason."""
    import numpy as np

    from phish_triage.data import dedup
    from phish_triage.data.inbox import sender_group

    test_senders = {sender_group(r) for r in tests}
    perms = dedup.permutations()
    test_items = [dedup.make_item(r, perms) for r in tests]
    exact = {item.exact_key for item in test_items}
    signatures = [item.hashvalues for item in test_items if item.hashvalues is not None]
    out = set()
    for email_id, record in records.items():
        item = dedup.make_item(record, perms)
        near = item.hashvalues is not None and any(
            float(np.mean(item.hashvalues == sig)) >= dedup.THRESHOLD for sig in signatures
        )
        if sender_group(record) in test_senders or item.exact_key in exact or near:
            out.add(email_id)
    return out


def build() -> dict:
    from phish_triage.data import inbox, privacymail

    base, _ = privacymail.load_split()
    records = read_masked()
    tests = list(inbox.read_split_records(set(base["test"])).values())
    left_out = like_a_test_email(records, tests)
    split = build_split(base, list(records), left_out)
    SPLIT_FILE.write_text(json.dumps({SPLIT: split}) + "\n")
    labels = [records[i]["label"] for i in split["train"] if i in records]
    return {
        "added to train": len(labels),
        "phish": labels.count("phish"),
        "legit": labels.count("legit"),
        "left out (a test email's sender, or a copy of one)": len(left_out),
    }


def load_split() -> dict[str, list[str]]:
    return json.loads(SPLIT_FILE.read_text())[SPLIT]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pull", metavar="BUCKET", help="move the sent emails out of this bucket")
    parser.add_argument("--build", action="store_true", help="build the with_retraining split")
    args = parser.parse_args(argv)
    if args.pull:
        print(json.dumps(pull(args.pull)))
    if args.build:
        print(json.dumps(build()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
