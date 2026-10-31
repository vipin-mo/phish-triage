import re

from phish_triage.data.sources import APACHE_LISTS, PHISHING_POT_COMMIT, SOURCES


def test_every_file_has_a_known_label_and_a_unique_https_url():
    for source in SOURCES.values():
        assert source.files, source.name
        assert len({f.filename for f in source.files}) == len(source.files)
        for remote in source.files:
            assert remote.label in {"phish", "legit", "spam"}
            assert remote.url.startswith("https://")


def test_apache_covers_every_month_for_every_list():
    months = 12 * (2026 - 2015) + 9  # 2015-01 .. 2026-09
    assert len(SOURCES["apache"].files) == months * len(APACHE_LISTS)


def test_phishing_pot_is_pinned_to_a_full_commit_sha():
    assert re.fullmatch(r"[0-9a-f]{40}", PHISHING_POT_COMMIT)
    assert PHISHING_POT_COMMIT in SOURCES["phishing_pot"].files[0].url


def test_spam_is_never_labelled_phishing():
    labels = {f.label for f in SOURCES["spamassassin"].files}
    assert labels == {"legit", "spam"}
