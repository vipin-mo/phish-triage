import math
from pathlib import Path

import numpy as np

from phish_triage.data.mask import mask_record
from phish_triage.data.parse import parse_email
from phish_triage.features import domains
from phish_triage.features.extract import FEATURE_NAMES, HEADER_FEATURES, extract, matrix
from phish_triage.features.sender import check_sender

FIXTURES = Path(__file__).parent / "fixtures"
RANKS = domains.DomainRanks({"example.com": 5_000, "paypal.com": 50, "gmail.com": 10})


def _record(name: str, masked: bool = True) -> dict:
    record = parse_email((FIXTURES / name).read_bytes(), source="t", label="phish", origin=name).to_dict()
    return mask_record(record) if masked else record


def test_spoofed_brand_email_lights_up_the_phishing_signals():
    f = extract(_record("spoofed_brand.eml"), RANKS)
    for name in (
        "from_lookalike",
        "display_name_brand_mismatch",
        "reply_to_differs",
        "reply_to_free_mail_differs",
        "ip_url",
        "shortener_url",
        "brand_mentioned_not_linked",
        "html_form",
        "password_input",
        "risky_attachment",
        "html_attachment",
        "recipient_address_in_body",
    ):
        assert f[name] == 1.0, name
    assert f["link_text_mismatch"] == math.log1p(1)  # shows paypal.com, goes to an IP
    assert f["from_log_rank"] == domains.UNRANKED_LOG_RANK
    assert f["urgency_terms"] > 0 and f["credential_terms"] > 0
    assert f["dkim_signed"] == 0.0


def test_clean_newsletter_does_not():
    f = extract(_record("clean_newsletter.eml"), RANKS)
    for name in (
        "from_lookalike",
        "display_name_brand_mismatch",
        "reply_to_differs",
        "ip_url",
        "shortener_url",
        "link_text_mismatch",
        "html_form",
        "risky_attachment",
    ):
        assert f[name] == 0.0, name
    assert f["dkim_aligned"] == 1.0
    assert f["from_log_rank"] == math.log10(5_000)


def test_text_only_emails_get_missing_header_features_not_zero():
    record = {"headers": [], "subject": "Verify your account", "text": "Click here", "html": "", "urls": []}
    f = extract(record, RANKS)
    assert all(math.isnan(f[name]) for name in HEADER_FEATURES)
    assert f["n_urls"] == 0.0 and f["credential_terms"] > 0


def test_rank_features_are_missing_without_a_rank_list():
    f = extract(_record("clean_newsletter.eml"), ranks=None)
    assert math.isnan(f["from_log_rank"]) and math.isnan(f["max_link_log_rank"])


def test_matrix_has_one_column_per_feature():
    x = matrix([_record("spoofed_brand.eml"), _record("clean_newsletter.eml")], RANKS)
    assert x.shape == (2, len(FEATURE_NAMES)) and np.isfinite(x).all()


def test_sender_check_fails_the_spoof_and_flags_the_forged_copy():
    check = check_sender(_record("spoofed_brand.eml", masked=False), RANKS)
    assert check.verdict == "fail"
    assert (check.spf, check.dkim, check.dmarc) == ("softfail", "none", "fail")
    text = " ".join(check.warnings)
    for expected in ("lower Authentication-Results", "looks like paypal", "display name says paypal", "gmail.com"):
        assert expected in text, expected


def test_sender_check_on_masked_record_uses_the_auth_field():
    check = check_sender(_record("spoofed_brand.eml"), RANKS)
    assert check.verdict == "fail"
    # the lower copies are gone after masking, but whether one claimed a pass is kept, so the warning still shows
    assert any("lower Authentication-Results" in w for w in check.warnings)


def test_sender_check_passes_an_aligned_newsletter():
    check = check_sender(_record("clean_newsletter.eml"), RANKS)
    assert check.verdict == "pass" and check.dkim_aligned and check.warnings == ()


def test_sender_check_without_results():
    check = check_sender({"headers": [["From", "a@example.com"]]})
    assert check.verdict == "none"


def test_lookalike_rules():
    assert domains.lookalike_brand("paypa1.com") == "paypal"
    assert domains.lookalike_brand("micros0ft-support.net") == "microsoft"
    assert domains.lookalike_brand("paypal.com.evil.test") == "paypal"
    for host in ("www.paypal.com", "login.microsoftonline.com", "purchase.com", "cloud.com", "stream.com"):
        assert domains.lookalike_brand(host) is None, host
    assert domains.has_confusable_letters("pаypal.com")  # Cyrillic "а"
    assert domains.registered_domain("login.paypal.co.uk") == "paypal.co.uk"
    assert not domains.looks_like_domain("John.Smith")
