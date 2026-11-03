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


BUNDLES = sorted(p for p in Path("artifacts/bundle").glob("*") if (p / "bundle.json").exists())


@pytest.mark.skipif(not BUNDLES, reason="needs a local bundle (`make bundle`); never in CI")
def test_the_real_bundle_scans_one_email_quickly():
    scanner = Scanner(BUNDLES[-1])
    scanner.scan(PLAIN)  # warm up
    started = time.perf_counter()
    result = scanner.scan(Path("tests/fixtures/spoofed_brand.eml").read_bytes())
    assert result.verdict in ("phish", "safe", "review") and time.perf_counter() - started < 2
