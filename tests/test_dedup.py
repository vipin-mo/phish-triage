from itertools import product
from string import ascii_lowercase

from phish_triage.data import dedup

PERMS = dedup.permutations()
WORDS = ["".join(p) for p in product(ascii_lowercase, repeat=3)]  # no digits: numbers are normalized away
BODY = " ".join(WORDS[:200])


def _item(id_, text, *, source="a", label="phish", date="2024-01-01", subject="Notice", html="", attachments=()):
    record = {"id": id_, "source": source, "label": label, "date": date, "subject": subject, "text": text}
    return dedup.make_item({**record, "html": html, "attachments": list(attachments)}, PERMS)


def test_exact_after_normalizing_numbers_links_and_addresses():
    a = _item("a", "Pay invoice 123 at https://x.test/1 or mail bob@x.test", date="2024-02-01")
    b = _item("b", "PAY invoice 999 at https://y.test/2?id=7 or mail eve@y.test", date="2024-01-01")
    result = dedup.find_duplicates([a, b])
    assert result.keep == {"b"}  # the earliest copy is kept
    assert result.duplicate_of == {"a": "b"}
    assert result.report["per_source"]["a/phish"]["exact_same_source"] == 1


def test_near_duplicates_are_grouped_and_distinct_texts_kept():
    near = BODY.replace(WORDS[100], "changed")
    other = " ".join(WORDS[1000:1200])
    result = dedup.find_duplicates([_item("a", BODY), _item("b", near, source="c"), _item("d", other)])
    assert result.keep == {"a", "d"}
    assert result.report["per_source"]["c/phish"]["near_other_source"] == 1


def test_short_texts_only_match_exactly():
    result = dedup.find_duplicates([_item("a", "click here now"), _item("b", "click here today")])
    assert result.keep == {"a", "b"}
    assert result.report["per_source"]["a/phish"]["short_text"] == 2


def test_groups_that_mix_labels_are_dropped():
    result = dedup.find_duplicates([_item("a", BODY), _item("b", BODY, label="legit"), _item("c", "unrelated")])
    assert result.keep == {"c"}
    assert result.conflicts == {"a", "b"}


def test_undated_copy_is_not_preferred():
    result = dedup.find_duplicates([_item("a", BODY, date=""), _item("b", BODY, date="2025-01-01")])
    assert result.keep == {"b"}


def test_empty_emails_are_dropped_not_grouped():
    result = dedup.find_duplicates([_item("a", "", subject=""), _item("b", "", subject="", label="legit")])
    assert result.empty == {"a", "b"} and not result.keep and not result.conflicts
    assert result.report["per_source"]["a/legit"]["empty"] == 1


def test_short_fallback_text_is_compared_with_the_html_and_attachments():
    fallback = "Your email client cannot display this message."
    a = _item("a", fallback, html=f"<p>{BODY}</p>")
    b = _item("b", fallback, html="<p>" + " ".join(WORDS[2000:2200]) + "</p>", label="legit")
    pdf = _item("c", "see attached", attachments=[{"content_type": "application/pdf"}])
    zip_ = _item("d", "see attached", attachments=[{"content_type": "application/zip"}])
    result = dedup.find_duplicates([a, b, pdf, zip_])
    assert result.keep == {"a", "b", "c", "d"}
