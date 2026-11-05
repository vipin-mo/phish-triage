"""Rules around the classifier: cases where a score shouldn't decide on its own.

**Signed by its own well-known domain (an experiment, Phase 7; not used by the scanner).** The real-use false alarms
(a bank's and a ride app's notices) were flagged by their words though each was signed by the brand's own domain with
every link on it. `own_domain_signed` says whether an email is like that; the experiment (`evaluation/own_domain.py`)
measures sending such flagged emails to review instead of marking them phishing. The rule was set before the run;
it moved as many phishing emails to review as false alarms (reports/own_domain.md), so the scanner doesn't use it.

**Too little text.** The text models judge what an email says. An email that shows almost no words but carries
images or attachments (an image-only or QR-code email, or one whose content is all in an attachment) gives them
nothing to judge, so its score says little either way. Such an email goes to review instead of being marked safe.
"""

from __future__ import annotations

from phish_triage.features.html import summarize_html
from phish_triage.models.baselines import body_text

LITTLE_TEXT_WORDS = 20  # visible words in the body, subject not counted
OWN_DOMAIN_TOP = 100_000  # the sender's domain must be among this many in the Tranco list


def too_little_text(record: dict, words: int = LITTLE_TEXT_WORDS) -> bool:
    """Counted on what the text models read (`body_text`). Known limit: an image email whose HTML shows almost
    nothing but carries 20 words of hidden text, or a plain-text part with them, isn't sent to review. Counting only
    the visible HTML words would catch that, but legitimate image newsletters are built the same way (a hidden
    preview line, a plain-text alternative): the deployed cascade would flag or send to review 22.5% of my inbox's
    test emails instead of 2.0%, and 6.1% of the held-out newsletters instead of 1.8%, for 0.4 points more of the
    public test's phishing. Reading the image itself (OCR, QR codes) is the real fix.

    It reads with reader 1 even when the bundle reads with reader 2. Measured with the reader-2 bundle on 2026-11-05:
    reader 2 would send 24 of my inbox's 249 test emails and 131 of the 3,738 held-out newsletters to review (0 and
    35 with reader 1), and no more phishing on any test, because newsletters hide their preview line with a
    `<style>` rule that reader 2 applies."""
    if len(body_text(record).split()) >= words:
        return False
    images = summarize_html(record.get("html") or "").images if record.get("html") else 0
    return images > 0 or bool(record.get("attachments"))


def own_domain_signed(record: dict, ranks) -> bool:
    """Authenticated as its own domain (the sender check passes, with a DKIM signature from the From domain), with no
    sender-check warning, from a domain in the Tranco top 100,000, and with at least one link, every one of them on
    that domain."""
    import math

    from phish_triage.features.domains import registered_domain, url_host
    from phish_triage.features.sender import check_sender, identity

    check = check_sender(record, ranks)
    if check.verdict != "pass" or not check.dkim_aligned or check.warnings:
        return False
    domain = identity(record.get("headers") or []).domain
    if not domain or ranks.log_rank(domain) > math.log10(OWN_DOMAIN_TOP):
        return False
    links = {registered_domain(url_host(u)) for u in record.get("urls") or []}
    return bool(links) and links == {domain}
