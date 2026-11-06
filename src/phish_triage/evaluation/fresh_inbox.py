"""The model in service on mail that came after it was chosen: my test inbox's second export (reports/fresh_inbox.md).

    python -m phish_triage.evaluation.fresh_inbox    # or `make fresh-inbox`; $0, local only, counts only

Every test set in the README was scored for each model I compared, and the model in service was picked on them, so
they are closer to validation numbers than to a fresh test. The second Takeout export of my test inbox
(data/private/test_inbox/test_inbox_2.mbox) holds the same account's mail, now with the emails that arrived later.
Only the emails that weren't in the first export count (matched by Message-ID, then by content: a re-export can
change an email's label header), grouped by sender as the `with_inbox` split grouped them:

- **held-out senders:** the 26 test senders, never in training; these emails weren't in any set a model was chosen
  on, so this is the untouched false-alarm test;
- **training senders:** senders some of whose earlier emails were trained on; a weaker test of the same templates;
- **new senders:** senders in neither export's split;
- **Spam:** Gmail's Spam folder, reported on its own (the folder isn't a label).

Each email is masked as in training and scored one at a time with the deployed bundle. Nothing from the emails is
printed or written, only counts; nothing is sent to an LLM.
"""

from __future__ import annotations

import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPORTS_DIR = Path("reports")
SECOND_EXPORT = Path("data/private/test_inbox/test_inbox_2.mbox")
GROUPS = ("held-out senders", "training senders", "new senders", "spam folder")


def wilson(k: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    if not n:
        return (math.nan, math.nan)
    p, d = k / n, 1 + z * z / n
    centre, half = p + z * z / (2 * n), z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, (centre - half) / d), min(1.0, (centre + half) / d))


def message_id(record: dict) -> str:
    return next((v.strip() for k, v in record.get("headers") or [] if k.lower() == "message-id"), "")


def new_emails() -> tuple[dict[str, list[dict]], dict]:
    """(group -> the second export's emails that weren't in the first, counts about the matching)."""
    from phish_triage.data import inbox

    first, _, _ = inbox.load_inbox(inbox.MBOX)
    first_ids, first_mids = {r["id"] for r in first}, {m for r in first if (m := message_id(r))}
    group = {r["id"]: inbox.sender_group(r) for r in first}
    split, slices = inbox.load_split()
    trained = {group[i] for part in ("train", "val") for i in split[part] if i in group}
    held_out = {group[i] for i in slices["inbox_test"] if i in group}

    second, _, _ = inbox.load_inbox(SECOND_EXPORT)
    out: dict[str, list[dict]] = defaultdict(list)
    counts: Counter = Counter(second_export=len(second))
    for r in second:
        if r["id"] in first_ids or (message_id(r) and message_id(r) in first_mids):
            counts["in the first export"] += 1
            continue
        g = inbox.sender_group(r)
        name = (
            "spam folder"
            if r["label"] == "spam"
            else "held-out senders"
            if g in held_out
            else "training senders"
            if g in trained
            else "new senders"
        )
        out[name].append(r)
    counts["new"] = sum(len(v) for v in out.values())
    return out, dict(counts)


def measure() -> dict:
    from phish_triage.data import inbox
    from phish_triage.data.mask import mask_record
    from phish_triage.service.bundle import DEPLOYED_SPLIT, latest
    from phish_triage.service.scanner import Scanner

    groups, matching = new_emails()
    scanner = Scanner(latest(split=DEPLOYED_SPLIT), threads=4)
    out: dict = {"bundle": scanner.version, "matching": matching, "groups": {}}
    for name in GROUPS:
        records = groups.get(name, [])
        flagged = review = 0
        per_sender: defaultdict[str, list[int]] = defaultdict(list)
        categories: Counter = Counter()
        for r in records:
            result = scanner.scan_record(mask_record(r))
            flagged += result.cascade_phish
            review += result.verdict == "review"
            per_sender[inbox.sender_group(r)].append(int(result.cascade_phish))
            categories[r.get("category")] += 1
        out["groups"][name] = {
            "emails": len(records),
            "senders": len(per_sender),
            "flagged": flagged,
            "sent_to_review": review,
            "flagged_per_sender_mean": (
                sum(sum(v) / len(v) for v in per_sender.values()) / len(per_sender) if per_sender else None
            ),
            "categories": dict(sorted(categories.items())),
        }
        print(name, {k: v for k, v in out["groups"][name].items() if k != "categories"}, file=sys.stderr)
    return out


def to_markdown(r: dict) -> str:
    def row(name: str) -> str:
        v = r["groups"][name]
        n, k = v["emails"], v["flagged"]
        if not n:
            return f"| {name.capitalize()} | 0 | | | | |"
        low, high = wilson(k, n)
        per_sender = v["flagged_per_sender_mean"]
        return (
            f"| {name.capitalize()} | {n:,} ({v['senders']} senders) | {k} ({k / n:.1%}) | {low:.1%}–{high:.1%} | "
            f"{per_sender:.1%} | {v['sent_to_review']} |"
        )

    m = r["matching"]
    return "\n".join(
        [
            "# My test inbox's later mail: a test no model was chosen on",
            "",
            f"Generated by `make fresh-inbox`. The deployed bundle (`{r['bundle']}`) on the emails of my test inbox's "
            f"second export that weren't in the first: {m.get('new', 0):,} of its {m.get('second_export', 0):,} "
            "(matched by Message-ID, then by content). Grouped by sender as the `with_inbox` split grouped them. "
            "Every email counts as legitimate except the Spam folder, which is shown on its own: the labels are "
            "Gmail's folders, not a hand check. Counts only; 95% Wilson intervals.",
            "",
            "| Senders | Emails | Flagged | 95% interval | Flagged, averaged per sender | Sent to review |",
            "|---|---:|---:|---:|---:|---:|",
            *[row(name) for name in GROUPS],
            "",
            "*Held-out senders* were never trained on, and these emails weren't in any set a model was chosen on: this "
            "row is the untouched test. *Training senders* had earlier emails in training, so their row is a weaker "
            "test of the same templates.",
            "",
        ]
    )


def main(argv: list[str] | None = None) -> int:
    path = REPORTS_DIR / "fresh_inbox.json"
    if not (argv and argv[0] == "report"):
        if not SECOND_EXPORT.exists():
            raise SystemExit(f"{SECOND_EXPORT} is missing")
        path.write_text(json.dumps(measure(), indent=1) + "\n")
    text = to_markdown(json.loads(path.read_text()))
    (REPORTS_DIR / "fresh_inbox.md").write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
