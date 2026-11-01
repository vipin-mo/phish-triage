"""Remove personal data from email text before it leaves our account (threat model, rule 7).

Adapted from the NexusAI redactor, for email: what the analyst needs as evidence stays, what identifies a person
goes.

- **Email addresses:** the part before the `@` is replaced, the domain is kept (`<USER>@paypa1-security.test`),
  because a look-alike domain is evidence and the mailbox name is personal data.
- **Phone numbers, card numbers (Luhn-checked), US social security numbers, IBANs, one-time codes** (4–8 digits
  next to "code", "OTP", "PIN", "verification") **and long account-like numbers** (9–18 digits) are replaced
  with typed placeholders such as `<PHONE>`.
- Kept: dates, money amounts, short numbers, IP addresses (an IP in a link is evidence) and domains.

Person names are not removed: that needs a named-entity model, which would add hundreds of megabytes to the Lambda
package. That is a known limit (docs/THREAT_MODEL.md).
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

_EMAIL = re.compile(r"(?<![\w.+-])[\w.%+-]+@((?:[\w-]+\.)+[A-Za-z]{2,})\b")
_OTP = re.compile(
    r"(?i)\b(code|otp|pin|passcode|verification|one[- ]time)([^\d\n]{0,25}?)(?<![\d,.])(\d{4,8})(?!\d|[.,]\d)"
)
_CARD = re.compile(r"(?<![\d-])(?:\d[ -]?){14,18}\d(?![\d-])")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,4})?\b")
_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_PHONE = re.compile(
    r"(?<![\w-])(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?![\w-])"
    r"|(?<![\w-])\+\d{1,3}[\s.-]\d{2,4}[\s.-]\d{3,4}[\s.-]\d{3,4}(?![\w-])"
)
_ACCOUNT = re.compile(r"(?<![\w.,/-])\d{9,18}(?![\w/-]|[.,]\d)")
_CARD_PREFIX = re.compile(r"^(?:4|5[1-5]|2[2-7]|3[47]|6011|65)")  # Visa, Mastercard, Amex, Discover


def luhn_ok(digits: str) -> bool:
    """A real card number: 15–19 digits, a known issuer prefix and a valid Luhn checksum."""
    nums = [int(d) for d in digits if d.isdigit()]
    if not 15 <= len(nums) <= 19 or not _CARD_PREFIX.match("".join(map(str, nums))):
        return False
    total = 0
    for i, n in enumerate(reversed(nums)):
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


@dataclass
class Redaction:
    text: str
    counts: dict[str, int] = field(default_factory=dict)


def redact(text: str) -> Redaction:
    counts: Counter[str] = Counter()

    def sub(kind: str, pattern: re.Pattern[str], value: str, keep=None) -> str:
        def repl(m: re.Match[str]) -> str:
            if keep and keep(m):
                return m.group(0)
            counts[kind] += 1
            return f"<{kind}>"

        return pattern.sub(repl, value)

    def email(m: re.Match[str]) -> str:
        counts["EMAIL"] += 1
        return f"<USER>@{m.group(1)}"

    text = _EMAIL.sub(email, text)

    def otp(m: re.Match[str]) -> str:
        counts["CODE"] += 1
        return f"{m.group(1)}{m.group(2)}<CODE>"

    text = _OTP.sub(otp, text)
    text = sub("CARD", _CARD, text, keep=lambda m: not luhn_ok(m.group(0)))
    text = sub("IBAN", _IBAN, text)
    text = sub("SSN", _SSN, text)
    text = sub("PHONE", _PHONE, text)
    text = sub("NUMBER", _ACCOUNT, text)
    return Redaction(text, dict(counts))
