"""Build every evaluation split, with fixed seeds, from the masked and de-duplicated emails.

    python -m phish_triage.data.splits

Each split answers a different question:

- `random`: the "normal" number, on the month-matched main pool (2015-01 to 2026-09).
- `by_source/*`: train on one phishing source, test on the other. Does the model work on phishing it never saw?
- `by_time`: train on mail up to 2022, test on 2023 onwards. Does it age?
- `by_time_nazario`: the same question inside one phishing source, so time and source aren't mixed up.
- `old_era`: Nazario 2004-2014 vs SpamAssassin 2002. Deliberately confounded (the classes come from different
  years), the way the course project's data was. Used only to show how inflated such a score is.
- `spam`: SpamAssassin spam, test only, as a "hard negative" slice (spam is not phishing).

**Month matching.** In the main pool, every month has the same number of phishing and legitimate emails (the
larger side is sampled down), so the date alone tells a model nothing about the label. 2026 is the one year where
legitimate mail is the smaller side, so phishing is sampled down there.

Writes data/splits/splits.json (ids per split and part) and data/splits/summary.json (counts only).
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from phish_triage.data.build import INTERIM_DIR
from phish_triage.data.sources import APACHE_FIRST_MONTH, APACHE_LAST_MONTH

SPLITS_DIR = Path("data/splits")
SEED = 20261029
MAIN_PHISH = ("nazario", "phishing_pot")
MAIN_LEGIT = ("apache",)
MAIN_FIRST, MAIN_LAST = f"{APACHE_FIRST_MONTH:%Y-%m}", f"{APACHE_LAST_MONTH:%Y-%m}"
TIME_CUTOFF = "2022-12"  # by_time: train on months up to and including this one
NAZARIO_TIME_CUTOFF = "2020-12"
OLD_ERA_LAST = "2014-12"
TEST_FRACTION = VAL_FRACTION = 0.15


@dataclass(frozen=True)
class Email:
    id: str
    source: str
    label: str
    month: str | None  # "YYYY-MM" from the earliest Received hop


def build_splits(emails: list[Email], seed: int = SEED) -> dict[str, dict[str, list[str]]]:
    emails = sorted(emails, key=lambda e: e.id)  # input order never affects the result
    rng = lambda step: random.Random(f"{seed}:{step}")  # noqa: E731 - one independent stream per step

    main_phish = [e for e in emails if e.source in MAIN_PHISH and e.label == "phish" and _in_main(e)]
    main_legit = [e for e in emails if e.source in MAIN_LEGIT and e.label == "legit" and _in_main(e)]
    pairs = month_matched(main_phish, main_legit, rng("match"))
    pool = [e for pair in pairs for e in pair]

    splits: dict[str, dict[str, list[str]]] = {"random": three_way(pool, rng("random"))}

    # by source: each legitimate email goes with the phishing email it was matched to, so both sides stay
    # month-matched.
    sides = {name: [e for pair in pairs if pair[0].source == name for e in pair] for name in MAIN_PHISH}
    for train_name, test_name in ((MAIN_PHISH[0], MAIN_PHISH[1]), (MAIN_PHISH[1], MAIN_PHISH[0])):
        train, val = _split_off(sides[train_name], VAL_FRACTION, rng(f"source:{train_name}"))
        splits[f"by_source/{train_name}_to_{test_name}"] = _ids(train=train, val=val, test=sides[test_name])

    splits["by_time"] = _time_split(pool, TIME_CUTOFF, rng("time"))
    splits["by_time_nazario"] = _time_split(sides["nazario"], NAZARIO_TIME_CUTOFF, rng("time:nazario"))

    old_era = [
        e
        for e in emails
        if (e.source == "nazario" and e.label == "phish" and e.month and e.month <= OLD_ERA_LAST)
        or (e.source == "spamassassin" and e.label == "legit")
    ]
    splits["old_era"] = three_way(old_era, rng("old_era"))
    splits["spam"] = _ids(test=[e for e in emails if e.source == "spamassassin" and e.label == "spam"])
    return splits


def month_matched(phish: list[Email], legit: list[Email], rng: random.Random) -> list[tuple[Email, Email]]:
    """Pair phishing and legitimate emails from the same month; the larger side of each month is sampled down."""
    by_month: defaultdict[str, tuple[list[Email], list[Email]]] = defaultdict(lambda: ([], []))
    for e in phish:
        by_month[e.month][0].append(e)
    for e in legit:
        by_month[e.month][1].append(e)
    pairs = []
    for month in sorted(by_month):
        p, lg = by_month[month]
        rng.shuffle(p)
        rng.shuffle(lg)
        pairs.extend(zip(p, lg, strict=False))
    return pairs


def three_way(emails: list[Email], rng: random.Random) -> dict[str, list[str]]:
    """Stratified train / val / test (70 / 15 / 15)."""
    rest, test = _split_off(emails, TEST_FRACTION, rng)
    train, val = _split_off(rest, VAL_FRACTION / (1 - TEST_FRACTION), rng)
    return _ids(train=train, val=val, test=test)


def summarize(splits: dict[str, dict[str, list[str]]], emails: list[Email]) -> dict:
    by_id = {e.id: e for e in emails}
    summary = {}
    for name, parts in splits.items():
        summary[name] = {}
        for part, ids in parts.items():
            members = [by_id[i] for i in ids]
            months = sorted(e.month for e in members if e.month)
            summary[name][part] = {
                "emails": len(members),
                "by_label": dict(sorted(Counter(e.label for e in members).items())),
                "by_source": dict(sorted(Counter(f"{e.source}/{e.label}" for e in members).items())),
                "months": [months[0], months[-1]] if months else None,
            }
    return summary


def _in_main(e: Email) -> bool:
    return e.month is not None and MAIN_FIRST <= e.month <= MAIN_LAST


def _split_off(emails: list[Email], fraction: float, rng: random.Random) -> tuple[list[Email], list[Email]]:
    """Move `fraction` of each label into a second list (stratified by label)."""
    keep, moved = [], []
    for label in sorted({e.label for e in emails}):
        group = [e for e in emails if e.label == label]
        rng.shuffle(group)
        cut = round(len(group) * fraction)
        moved += group[:cut]
        keep += group[cut:]
    return keep, moved


def _time_split(emails: list[Email], cutoff: str, rng: random.Random) -> dict[str, list[str]]:
    train, val = _split_off([e for e in emails if e.month <= cutoff], VAL_FRACTION, rng)
    return _ids(train=train, val=val, test=[e for e in emails if e.month > cutoff])


def _ids(**parts: list[Email]) -> dict[str, list[str]]:
    return {part: sorted(e.id for e in members) for part, members in parts.items()}


def load_emails(in_dir: Path = INTERIM_DIR) -> list[Email]:
    """Every email that survived duplicate removal, from the index written by `prepare.py`."""
    index = json.loads((in_dir / "index.json").read_text())
    return [Email(e["id"], e["source"], e["label"], e["date"][:7] if e["date"] else None) for e in index if e["kept"]]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args(argv)
    emails = load_emails()
    splits = build_splits(emails, args.seed)
    summary = {"seed": args.seed, "splits": summarize(splits, emails)}
    SPLITS_DIR.mkdir(parents=True, exist_ok=True)
    (SPLITS_DIR / "splits.json").write_text(json.dumps(splits) + "\n")
    (SPLITS_DIR / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    for name, parts in summary["splits"].items():
        print(f"{name}: " + ", ".join(f"{part} {info['emails']} {info['by_label']}" for part, info in parts.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
