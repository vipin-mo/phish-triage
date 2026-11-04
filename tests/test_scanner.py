import time
from pathlib import Path

import numpy as np
import pytest

from phish_triage.service.scanner import Scanner

PLAIN = (
    b"From: Shop <news@shop.example>\nTo: me@example.com\nSubject: Your order\n\n"
    + b"Thanks for your order, it ships on Monday and the receipt is attached to your account page today. " * 3
)
IMAGE_ONLY = (
    b"From: Shop <news@shop.example>\nTo: me@example.com\nSubject: Hi\nMIME-Version: 1.0\n"
    b"Content-Type: text/html\n\n<html><body><img src='https://cdn.example/a.png'> Scan me</body></html>\n"
)


class _Proba:
    def __init__(self, p):
        self.p = p

    def predict_proba(self, x):
        return np.array([[1 - self.p, self.p]] * len(x))


class _Tfidf:
    def transform(self, texts):
        return np.zeros((len(texts), 1))


class _Distilbert:
    def __init__(self, q):
        self.q, self.calls = q, 0

    def score(self, texts):
        self.calls += 1
        return np.array([self.q] * len(texts))


def fake(stacked: float, distilbert: float = 0.0) -> Scanner:
    s = Scanner.__new__(Scanner)
    s.config = {"stage1_cutoffs": {"low": 0.05, "high": 0.95}, "distilbert_threshold": 0.3}
    s.version = "test"
    s._tfidf, s._lr, s._stacked = _Tfidf(), _Proba(0.5), _Proba(stacked)
    s._ranks, s._distilbert = None, _Distilbert(distilbert)
    return s


def test_stage_1_decides_when_sure_and_distilbert_only_otherwise():
    sure = fake(0.99)
    r = sure.scan(PLAIN)
    assert (r.verdict, r.stage, sure._distilbert.calls) == ("phish", "stacked", 0)
    assert fake(0.01).scan(PLAIN).verdict == "safe"
    unsure = fake(0.5, distilbert=0.6)
    r = unsure.scan(PLAIN)
    assert (r.verdict, r.stage, unsure._distilbert.calls) == ("phish", "distilbert", 1)
    assert fake(0.5, distilbert=0.1).scan(PLAIN).verdict == "safe"


def test_an_image_with_almost_no_text_goes_to_review_unless_flagged():
    r = fake(0.01).scan(IMAGE_ONLY)
    assert (r.verdict, r.little_text, r.cascade_phish) == ("review", True, False)
    assert fake(0.99).scan(IMAGE_ONLY).verdict == "phish"


def test_the_scanner_masks_the_recipient_before_the_models_see_it():
    seen = {}
    s = fake(0.5, distilbert=0.1)
    s._distilbert.score = lambda texts: seen.setdefault("t", texts) and np.array([0.1])
    s.scan(PLAIN.replace(b"Thanks for", b"Hi me@example.com, thanks for"))
    assert "me@example.com" not in seen["t"][0]


HAS_BUNDLE = any((p / "bundle.json").exists() for p in Path("artifacts/bundle").glob("*"))


@pytest.mark.skipif(not HAS_BUNDLE, reason="needs a local bundle (`make bundle`); never in CI")
def test_the_real_bundle_scans_one_email_quickly():
    from phish_triage.service.bundle import latest

    scanner = Scanner(latest())
    scanner.scan(PLAIN)  # warm up
    started = time.perf_counter()
    result = scanner.scan(Path("tests/fixtures/spoofed_brand.eml").read_bytes())
    assert result.verdict in ("phish", "safe", "review") and time.perf_counter() - started < 2


def test_the_sender_warnings_returned_and_stored_name_no_domain():
    # From paypa1-security.test, Reply-To gmail.com: the raw warnings name both domains
    result = fake(0.99).scan(Path("tests/fixtures/spoofed_brand.eml").read_bytes())
    text = " ".join(result.sender["warnings"])
    assert "look like" in text or "looks like" in text
    assert "paypa1" not in text and "gmail" not in text and "@" not in text


def test_scanning_an_email_with_links_makes_no_network_call(monkeypatch):
    # Threat model rule 1: URLs are parsed as strings; nothing is fetched or resolved.
    import socket

    def refuse(*args, **kwargs):
        raise AssertionError("network call during a scan")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    raw = Path("tests/fixtures/html_link_and_attachment.eml").read_bytes()
    assert fake(0.5, distilbert=0.9).scan(raw).verdict == "phish"
    assert fake(0.99).scan(Path("tests/fixtures/spoofed_brand.eml").read_bytes()).verdict == "phish"


def test_latest_picks_the_newest_bundle_or_the_newest_of_one_split(tmp_path):
    import json

    from phish_triage.service.bundle import latest

    for name, split, created in [
        ("b", "with_inbox", "2026-11-04T01:00:00+00:00"),
        ("a", "with_newsletters", "2026-11-04T02:00:00+00:00"),
        ("c", "with_inbox", "2026-11-03T01:00:00+00:00"),
    ]:
        (tmp_path / name).mkdir()
        (tmp_path / name / "bundle.json").write_text(json.dumps({"split": split, "created": created}))
    assert latest(tmp_path).name == "a"
    assert latest(tmp_path, split="with_inbox").name == "b"
    with pytest.raises(SystemExit):
        latest(tmp_path, split="random")


def test_known_limit_hidden_or_plain_text_filler_lifts_an_image_email_out_of_review():
    # Kept on purpose (see triage.too_little_text): legitimate image newsletters look the same. A change here is a
    # decision, so this test pins it.
    from phish_triage.data.mask import mask_record
    from phish_triage.data.parse import parse_email
    from phish_triage.service.triage import too_little_text

    filler = b"Thanks for being with us this season and we hope the weather stays good for the family and friends " * 2
    head = b"From: Bank <a@bank.example>\nTo: me@example.com\nSubject: Scan\nMIME-Version: 1.0\n"
    hidden = head + b"Content-Type: text/html\n\n<html><body><img src='cid:qr'><div style='display:none'>" + filler
    hidden += b"</div></body></html>\n"
    alternative = (
        head
        + b"Content-Type: multipart/alternative; boundary=X\n\n--X\nContent-Type: text/plain\n\n"
        + filler
        + b"\n--X\nContent-Type: text/html\n\n<html><body><img src='cid:qr'></body></html>\n--X--\n"
    )
    for raw in (hidden, alternative):
        assert not too_little_text(mask_record(parse_email(raw, source="t", label="phish", origin="x").to_dict()))
    visible = head + b"Content-Type: text/html\n\n<html><body><img src='cid:qr'><p>" + filler + b"</p></body></html>\n"
    assert not too_little_text(mask_record(parse_email(visible, source="t", label="phish", origin="x").to_dict()))
