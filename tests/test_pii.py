from phish_triage.service.pii import luhn_ok, redact


def test_email_local_part_goes_domain_stays():
    r = redact("Write to jane.doe+x@paypa1-security.test or support@example.com")
    assert r.text == "Write to <USER>@paypa1-security.test or <USER>@example.com"
    assert r.counts == {"EMAIL": 2}


def test_codes_phones_cards_and_ids():
    text = (
        "Your verification code is 482913. Call +1 415-555-0134. Card 4111 1111 1111 1111. "
        "SSN 123-45-6789. IBAN DE89 3704 0044 0532 0130 00. Account 0012345678901."
    )
    r = redact(text)
    for placeholder in ("<CODE>", "<PHONE>", "<CARD>", "<SSN>", "<IBAN>", "<NUMBER>"):
        assert placeholder in r.text, placeholder
    assert "482913" not in r.text and "4111" not in r.text and "6789" not in r.text


def test_evidence_and_ordinary_numbers_are_kept():
    text = "Pay $1,250.00 by 2026-03-15 at http://198.51.100.7/login. Order 1234567 (ref 42)."
    assert redact(text).text == text


def test_luhn():
    assert luhn_ok("4111111111111111")
    assert not luhn_ok("4111111111111112")
    assert not luhn_ok("1234567812345670")  # valid checksum, no card issuer prefix
