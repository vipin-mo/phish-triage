"""The sender check: is the sender who they claim to be? A rule-based, user-visible result, not a learned feature.

It reads SPF, DKIM and DMARC only from the receiving provider's own `Authentication-Results` header, the topmost
one (threat model, rule 14). Lower copies may have been written by the sender, so they are ignored, and a lower
copy that claims "pass" when the provider's header doesn't is itself a warning. Nothing is re-verified with DNS:
the provider already did that, and old dataset emails can't be re-verified anyway because DKIM keys rotate.

"pass" means the domain in `From` really sent the email. It does not mean the email is safe: phishers' own
look-alike domains pass SPF and DKIM too, which is why look-alike and display-name warnings are reported next to it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email.utils import parseaddr

from phish_triage.data.mask import auth_results, lower_copy_claims_pass
from phish_triage.features.domains import (
    DomainRanks,
    address_domain,
    brands_in,
    is_official,
    lookalike_brand,
    registered_domain,
)

_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)=([a-z]+)")


@dataclass(frozen=True)
class SenderIdentity:
    display_name: str
    address: str
    host: str  # "mail.example.com"
    domain: str  # registered domain, "example.com"
    reply_to_domain: str
    dkim_domains: frozenset[str] = field(default_factory=frozenset)


def identity(headers: list) -> SenderIdentity:
    display_name, address = parseaddr(_first(headers, "from"))
    host = address_domain(address)
    reply_domain = registered_domain(address_domain(parseaddr(_first(headers, "reply-to"))[1]))
    dkim = {
        registered_domain(d)
        for key, value in headers
        if key.lower() == "dkim-signature"
        for d in re.findall(r"\bd=([^;\s]+)", value)
    }
    return SenderIdentity(
        display_name, address, host, registered_domain(host) if host else "", reply_domain, frozenset(dkim)
    )


@dataclass(frozen=True)
class SenderCheck:
    verdict: str  # "pass", "fail", "partial" (results present but not conclusive) or "none" (no results)
    spf: str | None
    dkim: str | None
    dmarc: str | None
    dkim_aligned: bool  # a DKIM signature from the From domain itself
    warnings: tuple[str, ...]


# Each warning by kind, and a sentence for it that names no domain: the warnings themselves name the sender's
# domains, so reports and the service's stored verdicts use these instead (threat model rule 8).
WARNING_TYPES = (
    ("A lower Authentication-Results", "forged lower auth header"),
    ("looks like", "look-alike domain"),
    ("The display name says", "display-name brand mismatch"),
    ("Replies go to", "Reply-To elsewhere"),
    ("not among the top 1 million", "unranked sender domain"),
)
WARNING_SENTENCES = {
    "forged lower auth header": "A lower Authentication-Results header claims a pass the provider did not give.",
    "look-alike domain": "The sender's domain looks like a well-known brand's domain but isn't it.",
    "display-name brand mismatch": "The display name names a brand the sender's address doesn't belong to.",
    "Reply-To elsewhere": "Replies go to a different domain than the sender's.",
    "unranked sender domain": "The sender's domain is not among the top 1 million domains.",
    "other": "Another sender-check warning.",
}


def warning_type(text: str) -> str:
    return next((kind for prefix, kind in WARNING_TYPES if prefix in text), "other")


def warning_sentence(text: str) -> str:
    return WARNING_SENTENCES[warning_type(text)]


def check_sender(record: dict, ranks: DomainRanks | None = None) -> SenderCheck:
    """Works on a parsed record (raw headers) or a masked one (which carries the topmost result in `auth`)."""
    headers = record.get("headers") or []
    auth = record["auth"] if "auth" in record else auth_results(headers)
    results = dict(_RESULT_RE.findall(auth or ""))
    spf, dkim, dmarc = results.get("spf"), results.get("dkim"), results.get("dmarc")
    sender = identity(headers)
    aligned = bool(sender.domain) and sender.domain in sender.dkim_domains

    if not results:
        verdict = "none"
    elif dmarc == "fail" or (spf in ("fail", "softfail") and dkim != "pass") or (dkim == "fail" and spf != "pass"):
        verdict = "fail"
    elif dmarc == "pass" or (dkim == "pass" and aligned):
        verdict = "pass"
    else:
        verdict = "partial"

    warnings = []
    lower_pass = (
        record["auth_lower_claims_pass"] if "auth_lower_claims_pass" in record else lower_copy_claims_pass(headers)
    )
    if verdict != "pass" and lower_pass:
        warnings.append("A lower Authentication-Results header claims a pass the provider did not give (ignored).")
    if sender.host and (brand := lookalike_brand(sender.host)):
        warnings.append(f"The sender's domain {sender.domain} looks like {brand} but is not {brand}'s.")
    for brand in sorted(brands_in(sender.display_name)):
        if not is_official(sender.domain, brand):
            warnings.append(f"The display name says {brand}, but the address is at {sender.domain or 'no domain'}.")
    if sender.reply_to_domain and sender.reply_to_domain != sender.domain:
        warnings.append(f"Replies go to {sender.reply_to_domain}, not to the sender's domain {sender.domain}.")
    if ranks and sender.domain and ranks.log_rank(sender.domain) > 6:
        warnings.append(f"The sender's domain {sender.domain} is not among the top 1 million domains.")
    return SenderCheck(verdict, spf, dkim, dmarc, aligned, tuple(warnings))


def _first(headers: list, name: str) -> str:
    return next((value for key, value in headers if key.lower() == name), "")
