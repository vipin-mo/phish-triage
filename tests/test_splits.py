import random
from collections import Counter

from phish_triage.data.splits import Email, build_splits

MONTHS = [
    f"{year}-{month:02d}" for year in range(2015, 2027) for month in range(1, 13) if f"{year}-{month:02d}" <= "2026-09"
]


def _emails(seed=0):
    rng = random.Random(seed)
    emails, n = [], 0
    for month in MONTHS:
        year = int(month[:4])
        for source, count in (("nazario", 3 if year <= 2022 else 1), ("phishing_pot", 0 if year < 2022 else 6)):
            for _ in range(count):
                emails.append(Email(f"p{n:05d}", source, "phish", month))
                n += 1
        for _ in range(rng.randint(2, 8)):  # sometimes fewer legit than phish, as in 2026
            emails.append(Email(f"l{n:05d}", "apache", "legit", month))
            n += 1
    for i in range(40):
        emails.append(Email(f"o{i:03d}", "nazario", "phish", "2006-05"))
        emails.append(Email(f"s{i:03d}", "spamassassin", "legit", "2002-08"))
        emails.append(Email(f"x{i:03d}", "spamassassin", "spam", "2002-08"))
    emails.append(Email("undated", "apache", "legit", None))
    return emails


def _months(ids, by_id, label):
    return Counter(by_id[i].month for i in ids if by_id[i].label == label)


def test_main_pool_is_month_matched_and_parts_do_not_overlap():
    emails = _emails()
    by_id = {e.id: e for e in emails}
    random_split = build_splits(emails)["random"]
    pool = [i for part in random_split.values() for i in part]
    assert len(pool) == len(set(pool))
    assert _months(pool, by_id, "phish") == _months(pool, by_id, "legit")
    assert "undated" not in pool and not any(by_id[i].source == "spamassassin" for i in pool)


def test_same_seed_same_splits_whatever_the_input_order():
    emails = _emails()
    shuffled = emails[:]
    random.Random(1).shuffle(shuffled)
    assert build_splits(emails) == build_splits(shuffled)
    assert build_splits(emails) != build_splits(emails, seed=7)


def test_by_source_tests_only_on_the_other_phishing_source():
    emails = _emails()
    by_id = {e.id: e for e in emails}
    split = build_splits(emails)["by_source/nazario_to_phishing_pot"]
    train_sources = {by_id[i].source for i in split["train"] + split["val"]}
    test_sources = {by_id[i].source for i in split["test"]}
    assert train_sources == {"nazario", "apache"}
    assert test_sources == {"phishing_pot", "apache"}
    assert not set(split["train"]) & set(split["test"])
    assert _months(split["test"], by_id, "phish") == _months(split["test"], by_id, "legit")


def test_by_time_trains_on_the_past_only():
    emails = _emails()
    by_id = {e.id: e for e in emails}
    splits = build_splits(emails)
    assert max(by_id[i].month for i in splits["by_time"]["train"]) <= "2022-12"
    assert min(by_id[i].month for i in splits["by_time"]["test"]) >= "2023-01"
    nazario = splits["by_time_nazario"]
    assert {by_id[i].source for i in nazario["test"]} == {"nazario", "apache"}
    assert max(by_id[i].month for i in nazario["train"]) <= "2020-12"


def test_old_era_and_spam_slices():
    splits = build_splits(_emails())
    old = [i for part in splits["old_era"].values() for i in part]
    assert len(old) == 80 and all(i[0] in "os" for i in old)
    assert sorted(splits["spam"]) == ["test"] and len(splits["spam"]["test"]) == 40
