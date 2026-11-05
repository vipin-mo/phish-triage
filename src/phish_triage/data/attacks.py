"""Training copies for the robustness defence (Phase 7.2, part 2): the `with_attacks` split.

    python -m phish_triage.data.attacks      # writes data/private/attacks/: the split and the copies

The deployed split (`with_retraining`) with one attacked copy of each of its training phishing emails added to its
training part; validation and test are unchanged. Each copy gets one of part 1's attacks (`evaluation/robustness.py`),
drawn at random with a fixed seed: look-alike letters, zero-width spaces, hidden HTML (any of its four tricks), bit.ly
links, or all four. The hidden text is never the test's paragraph: it is 300 to 400 words from legitimate training
emails of the public Apache lists, so no copy holds private mail. Only phishing gets copies; the clean tests show
whether that teaches the models that hidden HTML alone means phishing. The copies are masked records, like every
record they come from; the split file lists private emails' ids, so it stays in data/private/.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import random
import sys
from collections import Counter
from pathlib import Path

PRIVATE_DIR = Path("data/private/attacks")
MASKED = PRIVATE_DIR / "masked.jsonl.gz"
SPLIT_FILE = PRIVATE_DIR / "split.json"
SPLIT = "with_attacks"
SEED = 20261106
FILLER_WORDS = (300, 400)
TRAIN_ATTACKS = (
    "lookalike_letters",
    "hidden_characters",
    "hidden_html_display_none",
    "hidden_html_style_class",
    "hidden_html_off_screen",
    "hidden_html_tiny_text",
    "shortened_links",
    "all_four",
)


def filler(rng: random.Random, texts: list[str]) -> str:
    words: list[str] = []
    while len(words) < FILLER_WORDS[0]:
        words += rng.choice(texts).split()
    return " ".join(words[: FILLER_WORDS[1]])


def attacked_copy(record: dict, attack: str, hidden: str) -> dict:
    from phish_triage.evaluation import robustness as rb

    if attack == "all_four":
        copy = rb.all_four(record, hidden)
    elif attack.startswith("hidden_html_"):
        copy = rb.hidden_html(record, attack.removeprefix("hidden_html_"), filler=hidden)
    else:
        copy = rb.ATTACKS[attack](record)
    copy["id"] = hashlib.sha256(f"{record['id']}:{attack}".encode()).hexdigest()[:16]
    copy["attacked"], copy["attacked_from"] = attack, record["id"]
    return copy


def build_copies(base: dict[str, list[str]], records: dict[str, dict], seed: int = SEED) -> list[dict]:
    from phish_triage.models.baselines import body_text

    apache = [body_text(records[i]) for i in base["train"] if records[i]["source"] == "apache"]
    apache = [t for t in apache if len(t.split()) >= 20]
    rng = random.Random(seed)
    copies = []
    for email_id in base["train"]:
        if records[email_id]["label"] == "phish":
            attack = rng.choice(TRAIN_ATTACKS)
            copies.append(attacked_copy(records[email_id], attack, filler(rng, apache)))
    return copies


def build() -> dict:
    from phish_triage.data import inbox, retraining

    base = retraining.load_split()
    records = inbox.read_split_records(set(base["train"]))
    copies = build_copies(base, records)
    if leaked := {c["id"] for c in copies} & (set(base["train"]) | set(base["val"]) | set(base["test"])):
        raise SystemExit(f"{len(leaked)} copies collide with existing ids")
    PRIVATE_DIR.mkdir(parents=True, exist_ok=True)
    with gzip.open(MASKED, "wt", encoding="utf-8") as out:
        for copy in copies:
            out.write(json.dumps(copy, ensure_ascii=False) + "\n")
    split = {"train": base["train"] + [c["id"] for c in copies], "val": list(base["val"]), "test": list(base["test"])}
    SPLIT_FILE.write_text(json.dumps({SPLIT: split}) + "\n")
    return {
        "train": len(split["train"]),
        "copies": len(copies),
        "by_attack": dict(sorted(Counter(c["attacked"] for c in copies).items())),
        "copied_from_sources": dict(Counter(records[c["attacked_from"]]["source"] for c in copies)),
    }


def load_split() -> dict[str, list[str]]:
    return json.loads(SPLIT_FILE.read_text())[SPLIT]


def main() -> int:
    print(json.dumps(build(), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
