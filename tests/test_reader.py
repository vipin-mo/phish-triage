from phish_triage.data.parse import html_to_text
from phish_triage.features.extract import extract
from phish_triage.features.html import visible_html
from phish_triage.features.normalize import normalize_text
from phish_triage.models.baselines import body_text, email_text

SHOWN = "<p>Please confirm your account details today using the form below.</p>"


def page(head: str, hidden: str) -> str:
    return f"<html><head>{head}</head><body>{SHOWN}{hidden}</body></html>"


def test_normalize_removes_invisible_characters_and_fixes_mixed_words_only():
    assert normalize_text("pass​word ve⁠rify­") == "password verify"
    assert normalize_text("pаypаl") == "paypal"  # Cyrillic a inside a Latin word
    assert normalize_text("οnline") == "online"  # Greek omicron
    assert normalize_text("привет") == "привет"  # Russian
    assert normalize_text("Ｐａｙ") == "Pay"  # fullwidth
    assert normalize_text("plain ascii") == "plain ascii"


def test_reader_2_applies_style_blocks_outside_media_queries():
    cases = {
        "<style>.n{display:none}</style>": '<div class="n">secret words here now</div>',
        "<style>#p{visibility:hidden}</style>": '<div id="p">secret words here now</div>',
        "<style>aside{display:none}</style>": "<aside>secret words here now</aside>",
        "<style>div.a.b{font-size:1px}</style>": '<div class="b a c">secret words here now</div>',
    }
    for head, hidden in cases.items():
        html = page(head, hidden)
        assert "secret" in visible_html(html).text and "secret" not in visible_html(html, 2).text
        assert "Please confirm" in visible_html(html, 2).text
    responsive = page("<style>@media (max-width:600px){.n{display:none}}</style>", '<div class="n">secret words</div>')
    assert "secret" in visible_html(responsive, 2).text
    other = page("<style>.a .n{display:none}</style>", '<div class="n">secret words</div>')  # descendant: not simple
    assert "secret" in visible_html(other, 2).text


def test_reader_2_hides_off_screen_and_small_text_but_not_ordinary_text():
    for style in ("position:absolute;left:-9999px", "position:fixed;top:-500px", "font-size:2px", "font-size:3px"):
        html = page("", f'<div style="{style}">secret words here</div>')
        assert "secret" in visible_html(html).text and "secret" not in visible_html(html, 2).text
    for style in ("position:absolute;left:10px", "position:relative;left:-9999px", "font-size:12px", "font-size:0.8em"):
        assert "secret" in visible_html(page("", f'<div style="{style}">secret words here</div>'), 2).text


def test_reader_2_body_ignores_hidden_parts_when_the_html_shows_almost_nothing():
    html = (
        '<html><body><img src="cid:x"><div style="display:none">many hidden harmless words go here</div></body></html>'
    )
    record = {"subject": "Hi", "text": html_to_text(html), "html": html}
    assert "hidden harmless" in body_text(record)  # reader 1 falls back to the parser's text, hidden parts included
    assert "hidden harmless" not in body_text(record, 2)
    own = {"subject": "Hi", "text": "the plain-text part of its own", "html": html}
    assert body_text(own, 2) == "the plain-text part of its own"  # a real plain-text part is still read


def test_reader_2_text_and_features_see_the_cleaned_text():
    record = {
        "subject": "Urg​ent: verіfy",
        "headers": [["From", "a@b.example"]],
        "text": "Your account is sus​pended. Update your password immediately.",
        "html": "",
        "urls": [],
        "attachments": [],
    }
    assert "Urgent" in email_text(record, 2) and "suspended" in email_text(record, 2)
    assert extract(record, reader=2)["urgency_terms"] > extract(record)["urgency_terms"]
