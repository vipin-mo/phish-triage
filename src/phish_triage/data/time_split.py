"""Does the model catch phishing from months after its training? The private `with_time_split` split (batch 3).

    python -m phish_triage.data.time_split    # writes data/private/time_split/split.json; counts only

The deployed split (`with_normalized`) trained on 2026 phishing from every month, January to October, so its 2026
test is phishing from the same months and campaigns it trained on. This split takes every phishing email dated
`CUT` or later out of training and validation, so a model trained on it has seen phishing only up to July 2026.
Everything else is unchanged, the legitimate mail included (my inbox is October and November 2026): the question is
whether newer phishing gets through, not whether the model ages as a whole.

Its two phishing tests:

- **before the cut:** the deployed split's 2026 phishing test emails dated before `CUT` (same months as training);
- **after the cut:** every phishing email dated `CUT` or later, wherever the deployed split had put it.

The split lists private emails' ids, so it stays in data/private/.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PRIVATE_DIR = Path("data/private/time_split")
SPLIT_FILE = PRIVATE_DIR / "split.json"
SPLIT = "with_time_split"
CUT = "2026-08"  # phishing dated this month or later is never trained on


def build_split(base: dict[str, list[str]], test_2026: list[str], phish_month: dict[str, str]) -> tuple[dict, dict]:
    """(train/val/test ids, the two phishing test slices). `phish_month`: phishing id -> its "YYYY-MM"."""
    after = {i for i, month in phish_month.items() if month >= CUT}
    split = {
        "train": [i for i in base["train"] if i not in after],
        "val": [i for i in base["val"] if i not in after],
        "test": base["test"] + sorted(after - set(base["test"])),
    }
    slices = {
        "phish_before_cut": [i for i in test_2026 if phish_month.get(i, "") < CUT],
        "phish_after_cut": sorted(i for i in after if i in set(split["test"])),
    }
    return split, slices


def build() -> dict:
    from phish_triage.data import inbox, retraining
    from phish_triage.data.build import INTERIM_DIR
    from phish_triage.service.bundle import load_split

    base, slices = load_split(retraining.NORMALIZED_SPLIT)
    used = {i for part in base.values() for i in part}
    index = json.loads((INTERIM_DIR / "index.json").read_text())
    phish_month = {e["id"]: (e["date"] or "")[:7] for e in index if e["label"] == "phish" and e["id"] in used}
    # The private emails aren't in the public index: dated from their own records (phishing I sent for retraining)
    listed = {e["id"] for e in index}
    private = inbox.read_split_records({i for i in used if i not in listed})
    phish_month |= {i: (r.get("date") or "")[:7] for i, r in private.items() if r["label"] == "phish"}
    split, new = build_split(base, slices["phish_2026_test"], phish_month)
    PRIVATE_DIR.mkdir(parents=True, exist_ok=True)
    SPLIT_FILE.write_text(json.dumps({SPLIT: split, "slices": new}) + "\n")
    return {
        "train": len(split["train"]),
        "val": len(split["val"]),
        "taken out of train and val": len(base["train"]) + len(base["val"]) - len(split["train"]) - len(split["val"]),
        "phish before the cut (test)": len(new["phish_before_cut"]),
        "phish after the cut (test)": len(new["phish_after_cut"]),
    }


def load() -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    saved = json.loads(SPLIT_FILE.read_text())
    return saved[SPLIT], saved["slices"]


def load_split() -> dict[str, list[str]]:
    return load()[0]


def main(argv: list[str] | None = None) -> int:
    print(json.dumps(build(), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
