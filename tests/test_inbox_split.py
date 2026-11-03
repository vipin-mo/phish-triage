from phish_triage.data import inbox
from phish_triage.evaluation.with_inbox import without_dates


def _record(i: int, domain: str, label: str = "legit") -> dict:
    return {
        "id": f"{i:016x}",
        "label": label,
        "category": "spam" if label == "spam" else "updates",
        "headers": [["From", f"News <news@mail.{domain}>"]],
    }


def test_senders_are_spread_by_size_over_the_parts():
    groups = {"a": 500, "b": 100, "c": 90, "d": 5, "e": 4, "f": 3}
    assert inbox.assign_senders(groups) == {
        "a": "train", "b": "val", "c": "test", "d": "train", "e": "train", "f": "train"
    }  # fmt: skip


def test_split_keeps_senders_apart_caps_train_and_adds_matching_phishing():
    records = [_record(k, "big.example") for k in range(60)]  # one large sender
    records += [_record(100 + k, f"s{k}.example") for k in range(9) for _ in range(1)]
    records += [_record(200, "junk.example", "spam")]
    base = {"train": ["p1"], "val": ["p2"], "test": ["p3"]}
    phish = [f"x{k}" for k in range(200)]
    split, slices = inbox.build_split(records, base, phish)

    group = {r["id"]: inbox.sender_group(r) for r in records}
    parts = {part: {group[i] for i in ids if i in group} for part, ids in split.items()}
    assert not parts["train"] & parts["test"] and not parts["val"] & parts["test"] and not parts["train"] & parts["val"]
    big = inbox.sender_group(records[0])
    assert sum(group.get(i) == big for i in split["train"]) == inbox.PER_SENDER_CAP  # the largest goes to train
    inbox_train = [i for i in split["train"] if i in group]
    assert sum(i.startswith("x") for i in split["train"]) == len(inbox_train)  # as many 2026 phishing
    assert set(slices["phish_2026_test"]) == {i for i in split["test"] if i.startswith("x")}
    assert slices["spam_folder"] == [records[-1]["id"]]
    assert records[-1]["id"] not in {i for ids in split.values() for i in ids}
    assert split["train"][0] == "p1" and "p3" in slices["public_test"]


def test_date_words_are_removed_as_whole_words():
    assert without_dates("Your November 2026 statement, Mon 3 Nov").split() == ["Your", "statement,", "3"]
    assert without_dates("Monetize your mayonnaise") == "Monetize your mayonnaise"
