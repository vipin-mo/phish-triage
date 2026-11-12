"""Crafted inputs must not make the service hang or crash (regular-expression backtracking, quadratic parsing,
deep MIME nesting). Python manages memory itself, so these are the realistic equivalents of memory-safety bugs here.
"""

import time

import pytest

from phish_triage.data import dedup, mask, parse
from phish_triage.features import extract, html
from phish_triage.models import baselines
from phish_triage.service import analyst, pii

ATTACKS = ["a-." * 50_000, "a." * 50_000, "a" * 50_000, "a@" * 50_000, "1." * 50_000, ("a" * 60 + ".") * 2_000]
PATTERNS = {
    "dedup email": dedup._EMAIL_RE,
    "domain in link text": extract._DOMAIN_IN_TEXT,
    "mask domain": mask._DOMAIN_RE,
    "parse url": parse.URL_RE,
    "analyst url": analyst._URL,
    "ai instructions": analyst._AI_INSTRUCTIONS,
    "our tags": analyst._OUR_TAGS,
    "summary advice": analyst._ADVICE,
    "mask keep domains": mask._DOMAIN_LIKE_RE,
    "pii email": pii._EMAIL,
    "pii phone": pii._PHONE,
    "pii code": pii._OTP,
    "date words": baselines.DATE_WORDS,
    "fake signals block": baselines.FAKE_SIGNALS,
    "fake signal lines": baselines.SIGNAL_LINES,
    "clip lengths": html._UNIT_LENGTH,
}
# reader 3's patterns also meet our own markup repeated, which is what they look for
ATTACKS += ["<signals>" * 20_000, "<signals" * 20_000, "Classifier:" * 10_000, "rect(" + "0px" * 30_000]


def _seconds(fn) -> float:
    started = time.perf_counter()
    fn()
    return time.perf_counter() - started


@pytest.mark.parametrize("name", PATTERNS)
def test_patterns_stay_fast_on_crafted_input(name):
    worst = max(_seconds(lambda text=text: PATTERNS[name].findall(text)) for text in ATTACKS)
    assert worst < 1.0, f"{name} took {worst:.1f} s"


def test_deeply_nested_html_is_linear():
    assert _seconds(lambda: html.visible_html("<div>" * 100_000 + "x")) < 2.0


def test_deeply_nested_mime_does_not_crash():
    nested = b"Content-Type: multipart/mixed; boundary=b0\n\n" + b"".join(
        f"--b{i}\nContent-Type: multipart/mixed; boundary=b{i + 1}\n\n".encode() for i in range(2000)
    )
    records = []
    assert _seconds(lambda: records.append(parse.parse_email(nested, source="t", label="phish", origin="x"))) < 2.0
    assert records[0].parse_errors == ["MIME nesting too deep to parse"]
