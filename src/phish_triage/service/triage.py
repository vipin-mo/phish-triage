"""Rules around the classifier: cases where a score shouldn't decide on its own.

**Too little text.** The text models judge what an email says. An email that shows almost no words but carries
images or attachments (an image-only or QR-code email, or one whose content is all in an attachment) gives them
nothing to judge, so its score says little either way. Such an email goes to review instead of being marked safe.
"""

from __future__ import annotations

from phish_triage.features.html import summarize_html
from phish_triage.models.baselines import body_text

LITTLE_TEXT_WORDS = 20  # visible words in the body, subject not counted


def too_little_text(record: dict) -> bool:
    words = len(body_text(record).split())
    if words >= LITTLE_TEXT_WORDS:
        return False
    images = summarize_html(record.get("html") or "").images if record.get("html") else 0
    return images > 0 or bool(record.get("attachments"))
