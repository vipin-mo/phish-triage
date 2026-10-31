from datetime import UTC, datetime
from pathlib import Path

from phish_triage.data.parse import extract_urls, html_to_text, message_date, parse_email

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 10, 30, tzinfo=UTC)


def parse(name: str, label: str = "phish"):
    return parse_email((FIXTURES / name).read_bytes(), source="fixture", label=label, origin=name, now=NOW)


def test_date_comes_from_earliest_received_hop_not_the_forged_date_header():
    record = parse("received_dates.eml", "legit")
    # The last Received header is the first hop: 11:04 +0100 = 10:04 UTC. The Date header says 2000.
    assert record.date == "2024-03-12T10:04:00+00:00"
    assert record.date_from == "received"


def test_date_falls_back_to_date_header_then_none():
    headers = [("Date", "Wed, 05 Jun 2024 07:59:00 +0000")]
    assert message_date(headers, now=NOW) == (datetime(2024, 6, 5, 7, 59, tzinfo=UTC), "date_header")
    record = parse("no_usable_date.eml")
    assert (record.date, record.date_from) == (None, "none")


def test_future_and_ancient_dates_are_ignored():
    headers = [("Received", "by x; Mon, 01 Jan 2035 00:00:00 +0000"), ("Date", "Thu, 01 Jan 1970 00:00:00 +0000")]
    assert message_date(headers, now=NOW) == (None, "none")


def test_plain_text_urls_are_found_without_trailing_punctuation():
    record = parse("received_dates.eml", "legit")
    assert record.urls == ["https://billing.sender.example/invoice/42", "www.sender.example/help"]
    assert record.subject == "Your invoice is ready"


def test_html_email_keeps_link_target_and_shown_text_and_skips_scripts():
    record = parse("html_link_and_attachment.eml")
    # The href (real destination) and the URL shown as link text are both kept: their mismatch is a signal.
    assert record.urls == ["http://198.51.100.23/login.php", "https://www.paypal.com/verify"]
    assert "track.example" not in " ".join(record.urls)
    assert "Dear customer" in record.text  # text was derived from the HTML part
    assert "var tracking" not in record.text


def test_encoded_headers_are_decoded():
    record = parse("html_link_and_attachment.eml")
    headers = dict(record.headers)
    assert record.subject == "Action required: verify your account"
    assert headers["From"] == "PayPal Security <alerts@paypa1-security.example>"
    assert headers["Reply-To"] == "collect@other.example"


def test_attachments_are_described_not_kept():
    record = parse("html_link_and_attachment.eml")
    assert [(a.filename, a.content_type) for a in record.attachments] == [("invoice.zip", "application/zip")]
    assert record.attachments[0].size > 0
    assert "UEsDB" not in record.text + record.html


def test_record_id_is_stable_and_content_based():
    a, b = parse("received_dates.eml"), parse("received_dates.eml")
    assert a.id == b.id and len(a.id) == 16
    assert a.id != parse("no_usable_date.eml").id


def test_malformed_html_does_not_raise():
    assert html_to_text("<p>ok<a href='https://x.example'>link</p><<<</").startswith("ok")
    assert extract_urls("", "<a href=") == []
