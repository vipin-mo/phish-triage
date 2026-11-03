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


def test_newsletter_like_phishing_counts_real_links_not_their_log():
    import math

    from phish_triage.evaluation.with_inbox import NEWSLETTER_LINKS, newsletter_like_phish
    from phish_triage.features.extract import FEATURE_NAMES

    def row(aligned: int, links: int) -> list[float]:
        values = [0.0] * len(FEATURE_NAMES)
        values[FEATURE_NAMES.index("dkim_aligned")] = aligned
        values[FEATURE_NAMES.index("n_urls")] = math.log1p(links)  # as features.extract stores it
        return values

    features = {
        "a": row(1, NEWSLETTER_LINKS),
        "b": row(1, NEWSLETTER_LINKS - 1),
        "c": row(0, 40),
        "d": row(1, 40),
        "e": row(1, 40),
    }
    records = {i: {"label": "phish"} for i in "abcd"} | {"e": {"label": "legit"}}
    slices = {"public_test": ["a", "b", "c", "e"], "phish_2026_test": ["d"]}
    assert newsletter_like_phish(features, records, slices) == ["a", "d"]
