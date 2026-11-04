"""Rules around the classifier: cases where a score shouldn't decide on its own.

**Too little text.** The text models judge what an email says. An email that shows almost no words but carries
images or attachments (an image-only or QR-code email, or one whose content is all in an attachment) gives them
nothing to judge, so its score says little either way. Such an email goes to review instead of being marked safe.
"""

from __future__ import annotations

from phish_triage.features.html import summarize_html
from phish_triage.models.baselines import body_text

LITTLE_TEXT_WORDS = 20  # visible words in the body, subject not counted


def too_little_text(record: dict, words: int = LITTLE_TEXT_WORDS) -> bool:
    """Counted on what the text models read (`body_text`). Known limit: an image email whose HTML shows almost
    nothing but carries 20 words of hidden text, or a plain-text part with them, isn't sent to review. Counting only
    the visible HTML words would catch that, but legitimate image newsletters are built the same way (a hidden
    preview line, a plain-text alternative): the deployed cascade would flag or send to review 22.5% of my inbox's
    test emails instead of 2.0%, and 6.1% of the held-out newsletters instead of 1.8%, for 0.4 points more of the
    public test's phishing. Reading the image itself (OCR, QR codes) is the real fix."""
    if len(body_text(record).split()) >= words:
        return False
    images = summarize_html(record.get("html") or "").images if record.get("html") else 0
    return images > 0 or bool(record.get("attachments"))
