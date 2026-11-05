import io
import zipfile

from phish_triage.data import greco
from phish_triage.evaluation import robustness as rb
from phish_triage.features.html import visible_html
from phish_triage.models.baselines import body_text


def record(text="", html="", subject="Verify your account now", urls=None):
    return {
        "id": "abc123",
        "subject": subject,
        "headers": [["From", "a@b.example"], ["Subject", subject]],
        "text": text,
        "html": html,
        "urls": urls or [],
    }


PLAIN = "Please confirm your password at https://login.example.com/verify today.\nWrite to help@bank.example."
HTML = '<html><body><p style="color:red">Please confirm your password &amp; account</p><a href="https://x.example/a">here</a></body></html>'


def test_lookalike_letters_change_words_only_and_repeat():
    a = rb.lookalike_letters(record(PLAIN, urls=["https://login.example.com/verify"]))
    assert a == rb.lookalike_letters(record(PLAIN, urls=["https://login.example.com/verify"]))
    assert "https://login.example.com/verify" in a["text"] and "help@bank.example" in a["text"]
    assert any(ch in rb.CYRILLIC for ch in a["text"]) and any(ch in rb.CYRILLIC for ch in a["subject"])
    assert a["headers"][1] == ["Subject", a["subject"]]
    swapped = sum(ch in rb.CYRILLIC for ch in a["text"])
    twins = sum(ch in rb.TWINS for ch in "Please confirm your password at  today.\nWrite to .")
    assert 0.1 < swapped / twins < 0.5


def test_markup_entities_and_links_stay_in_html():
    for attack in (rb.lookalike_letters, rb.hidden_characters):
        a = attack(record(html=HTML, text="unrelated plain part"))
        assert (
            '<p style="color:red">' in a["html"] and 'href="https://x.example/a"' in a["html"] and "&amp;" in a["html"]
        )
        assert a["html"] != HTML


def test_derived_text_follows_the_html():
    from phish_triage.data.parse import html_to_text

    a = rb.hidden_characters(record(html=HTML, text=html_to_text(HTML)))
    assert a["text"] == html_to_text(a["html"]) and rb.ZERO_WIDTH in a["text"]


def test_hidden_characters_split_long_words_only():
    a = rb.hidden_characters(record("Go to the bank now https://bank.example/login"))
    assert "Go to the bank now" not in a["text"]
    assert "ba​nk" in a["text"] and "Go to the" in a["text"]
    assert "https://bank.example/login" in a["text"]


def test_hidden_html_puts_the_paragraph_first_and_plain_text_gets_an_html_part():
    a = rb.hidden_html(record(PLAIN), "display_none")
    assert a["text"] == PLAIN and a["html"].index(rb.HARMLESS[:20]) < a["html"].index("Please confirm")
    assert "https://login.example.com/verify" in a["urls"]
    # the control: the visible-text reader drops inline display:none, so the model reads the email's own words
    assert rb.HARMLESS[:20] not in body_text(a) and "Please confirm" in body_text(a)
    for trick in rb.HIDING:
        b = rb.hidden_html(record(html=HTML, text="x"), trick)
        assert b["html"].count(rb.HARMLESS[:20]) == rb.HIDDEN_COPIES
        assert "Please confirm" in visible_html(b["html"]).text


def test_hidden_html_at_the_end_goes_before_the_closing_body():
    b = rb.hidden_html(record(html=HTML, text="x"), "style_class", at_end=True)
    assert b["html"].index("Please confirm") < b["html"].index(rb.HARMLESS[:20]) < b["html"].index("</body>")
    assert b["html"].index(".note{display:none}") < b["html"].index("Please confirm")


def test_shortened_links_replace_every_link_and_keep_punctuation():
    a = rb.shortened_links(record("Go to https://login.example.com/verify. Or www.bank.example!", html=HTML))
    assert all(u.startswith("https://bit.ly/") for u in a["urls"]) and len(a["urls"]) == 3
    assert a["text"].count("https://bit.ly/") == 2 and ". Or" in a["text"] and a["text"].endswith("!")
    assert a == rb.shortened_links(record("Go to https://login.example.com/verify. Or www.bank.example!", html=HTML))


def test_all_four_and_the_attack_list():
    a = rb.all_four(record(PLAIN, urls=["https://login.example.com/verify"]))
    assert all(u.startswith("https://bit.ly/") for u in a["urls"]) and rb.ZERO_WIDTH in a["text"]
    assert ".note{display:none}" in a["html"]
    assert set(rb.ANALYST_ATTACKS) <= set(rb.ATTACKS) and set(rb.NAMES) == set(rb.ATTACKS)


def test_summary_counts_the_same_emails_lost():
    clean = [{"verdict": "phish", "stage": "stacked", "distilbert_phish": True}] * 3
    attacked = [
        {"verdict": "phish", "stage": "distilbert", "distilbert_phish": True},
        {"verdict": "safe", "stage": "distilbert", "distilbert_phish": False},
        {"verdict": "review", "stage": "stacked", "distilbert_phish": True},
    ]
    attacked[1]["hidden_read"] = True
    s = rb.summarize(attacked, clean)
    assert s["hidden_read"] == 1 and s["lost_with_hidden_read"] == 1
    assert s["flagged"] == 1 and s["lost"] == 2 and s["review"] == 1 and s["decided_by_stage_1"] == 1
    assert abs(s["distilbert_recall"] - 2 / 3) < 1e-9 and "lost" not in rb.summarize(clean)


def test_report_with_and_without_the_analyst():
    row = rb.summarize([{"verdict": "phish", "stage": "stacked", "distilbert_phish": True}])
    c = {
        "bundle": "b",
        "public_phish": {k: row for k in rb.ATTACKS},
        "greco_llm_phish": row,
        "greco_legit_file": row,
    }
    c["public_phish"]["hidden_html_display_none"] = row | {"lost": 1, "hidden_read": 2, "lost_with_hidden_read": 1}
    text = rb.to_markdown(c, None)
    assert "Not run yet" in text and "three hiding tricks give the same numbers" in text
    assert "still lost 1. The models read its hidden paragraph in 2 emails, 1 of the lost" in text
    a = {
        "prompt_version": 5,
        "llm_model": "m",
        "requests": 2,
        "schema_valid_rate": 1.0,
        "by_attack": {"clean": {"emails": 1, "verdicts": {"phish": 1}, "suggestions": {"phish": 1}}},
    }
    assert "| Clean | phish 1 | phish 1 |" in rb.to_markdown(c, a)


def test_greco_rows_are_joined_back_and_deduplicated(tmp_path):
    path = tmp_path / "greco.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(
            "llm-generated/phishing.csv", "text,label\nDear User, click here, now,1\nDear User, click here, now,1\n"
        )
        z.writestr("llm-generated/legit.csv", 'text,label\n"Dear Ann, see you, soon",1\n')
    rows = greco.llm_written(path)
    assert rows[0] == ("phish", "llm-generated/phishing.csv:2", "Dear User, click here, now")
    assert rows[2][0] == "legit" and rows[2][2] == "Dear Ann, see you, soon"
    records = greco.records(path)
    assert [r["label"] for r in records] == ["phish", "legit"] and records[0]["source"] == "greco"


def test_greco_refuses_unexpected_columns(tmp_path):
    import pytest

    path = tmp_path / "greco.zip"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        z.writestr("llm-generated/phishing.csv", "body,label\nx,1\n")
        z.writestr("llm-generated/legit.csv", "text,label\nx,1\n")
    path.write_bytes(buffer.getvalue())
    with pytest.raises(ValueError, match="unexpected columns"):
        greco.llm_written(path)
