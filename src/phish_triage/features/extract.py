"""Structured phishing signals for one masked email (see `data/mask.py`), as a fixed-order vector of numbers.

Every feature is a standard, explainable phishing signal: sender mismatches, deceptive links, risky attachments,
pressure and credential wording. They are computed from the masked record, the same view the service builds from
a live email, so training and serving see the same thing.

Rules:
- When an email has no headers at all (text-only datasets), every header feature is NaN ("missing"), never 0.
  Gradient-boosted trees handle NaN natively.
- Authentication results (`auth`) are not a feature: the leakage audit showed they identify the collecting
  server (AUC 0.993). They feed the rule-based sender check (`sender.py`) instead.
- Nothing is fetched: URLs are only parsed as strings.
"""

from __future__ import annotations

import math
import re
from email.utils import getaddresses
from urllib.parse import urlsplit

import numpy as np

from phish_triage.data.mask import PLACEHOLDER_ADDRESS
from phish_triage.features.domains import (
    FREE_MAIL,
    SHORTENERS,
    DomainRanks,
    brands_in,
    has_confusable_letters,
    is_ip,
    is_official,
    is_punycode,
    lookalike_brand,
    looks_like_domain,
    registered_domain,
    url_host,
)
from phish_triage.features.html import summarize_html
from phish_triage.features.sender import identity

TEXT_CHARS = 50_000
NAN = float("nan")

HEADER_FEATURES = (
    "from_missing",
    "from_free_mail",
    "from_log_rank",
    "from_lookalike",
    "display_name_brand_mismatch",
    "display_name_has_other_address",
    "reply_to_differs",
    "reply_to_free_mail_differs",
    "to_missing",
    "dkim_signed",
    "dkim_aligned",
)
LINK_FEATURES = (
    "n_urls",
    "n_link_domains",
    "ip_url",
    "punycode_url",
    "confusable_url",
    "lookalike_url",
    "shortener_url",
    "url_with_credentials",
    "http_share",
    "max_url_length",
    "max_subdomain_depth",
    "link_text_mismatch",
    "brand_mentioned_not_linked",
    "max_link_log_rank",
    "unranked_link_share",
    "has_html",
    "html_form",
    "password_input",
    "html_script",
    "n_images",
)
ATTACHMENT_FEATURES = ("n_attachments", "risky_attachment", "html_attachment", "archive_attachment", "macro_attachment")
TEXT_FEATURES = (
    "log_words",
    "urgency_terms",
    "credential_terms",
    "payment_terms",
    "exclamations",
    "recipient_address_in_body",
)
FEATURE_NAMES = HEADER_FEATURES + LINK_FEATURES + ATTACHMENT_FEATURES + TEXT_FEATURES

HTML_EXTENSIONS = frozenset({"html", "htm", "shtml", "xhtml", "svg"})
ARCHIVE_EXTENSIONS = frozenset({"zip", "rar", "7z", "gz", "tgz", "tar", "ace", "cab", "iso", "img", "vhd", "vhdx"})
MACRO_EXTENSIONS = frozenset({"docm", "xlsm", "pptm", "dotm", "xlam"})
EXECUTABLE_EXTENSIONS = frozenset(
    {"js", "jse", "vbs", "vbe", "wsf", "hta", "exe", "scr", "com", "bat", "cmd", "ps1", "lnk", "msi", "jar", "one"}
)
RISKY_EXTENSIONS = HTML_EXTENSIONS | ARCHIVE_EXTENSIONS | MACRO_EXTENSIONS | EXECUTABLE_EXTENSIONS


def _terms(*phrases: str) -> re.Pattern[str]:
    return re.compile(r"\b(?:" + "|".join(phrases) + r")", re.IGNORECASE)


URGENCY = _terms(
    "urgent", "immediately", "immediate action", "as soon as possible", r"within \d+ (?:hours|days)", "expir",
    "suspend", "deactivat", "final notice", "last warning", "act now", "limited time", "unusual activity",
    "unauthori[sz]ed", "locked", "restricted", "terminat",
)  # fmt: skip
CREDENTIALS = _terms(
    "password", "passcode", "log ?in", "sign ?in", "verify your", "confirm your", "update your", "validate",
    "account information", "username", "credentials", "social security", "security question",
)  # fmt: skip
PAYMENT = _terms(
    "invoice", "payment", "wire transfer", "bank transfer", "bitcoin", "crypto", "wallet", "gift card", "refund",
    "billing", "credit card", "overdue", "transaction", "claim", "reward", "prize",
)  # fmt: skip
# Bounded: the unbounded "(?:[a-z0-9-]+\.)+" backtracked badly on input like "a-.a-.a-." (103 s on 50k characters).
# Link text is also cut to LINK_TEXT_CHARS before searching.
_DOMAIN_IN_TEXT = re.compile(r"\b(?:https?://)?((?:[a-z0-9-]{1,63}\.){1,16}[a-z]{2,63})\b", re.IGNORECASE)
LINK_TEXT_CHARS = 300


def extract(record: dict, ranks: DomainRanks | None = None, reader: int = 1) -> dict[str, float]:
    """Reader 2 (Phase 7.2) counts the text features on what the text models read (`baselines.email_text`)."""
    features = {**_header_features(record, ranks), **_link_features(record, ranks)}
    features |= _attachment_features(record.get("attachments") or [])
    features |= _text_features(record, reader)
    return {name: float(features[name]) for name in FEATURE_NAMES}


def matrix(records: list[dict], ranks: DomainRanks | None = None, reader: int = 1) -> np.ndarray:
    return np.array([[row[name] for name in FEATURE_NAMES] for row in (extract(r, ranks, reader) for r in records)])


def _header_features(record: dict, ranks: DomainRanks | None) -> dict[str, float]:
    headers = record.get("headers") or []
    if not headers:
        return dict.fromkeys(HEADER_FEATURES, NAN)
    sender = identity(headers)
    reply_differs = bool(sender.reply_to_domain) and sender.reply_to_domain != sender.domain
    named = {a.lower() for a in re.findall(r"[\w.+-]+@[\w.-]+\w", sender.display_name)} - {sender.address.lower()}
    to = next((value for key, value in headers if key.lower() == "to"), "")
    return {
        "from_missing": not sender.domain,
        "from_free_mail": sender.domain in FREE_MAIL,
        "from_log_rank": ranks.log_rank(sender.domain) if ranks and sender.domain else NAN,
        "from_lookalike": bool(sender.host) and lookalike_brand(sender.host) is not None,
        "display_name_brand_mismatch": any(not is_official(sender.domain, b) for b in brands_in(sender.display_name)),
        "display_name_has_other_address": bool(named),
        "reply_to_differs": reply_differs,
        "reply_to_free_mail_differs": reply_differs and sender.reply_to_domain in FREE_MAIL,
        "to_missing": not any("@" in a for _, a in getaddresses([to])),
        "dkim_signed": bool(sender.dkim_domains),
        "dkim_aligned": bool(sender.domain) and sender.domain in sender.dkim_domains,
    }


def _link_features(record: dict, ranks: DomainRanks | None) -> dict[str, float]:
    urls = record.get("urls") or []
    hosts = [h for h in (url_host(u) for u in urls) if h]
    domains = {registered_domain(h) for h in hosts}
    html = record.get("html") or ""
    summary = summarize_html(html) if html else None
    with_scheme = [u for u in urls if u.lower().startswith(("http://", "https://"))]

    mismatches = 0
    for href, text in summary.links if summary else []:
        href_host = url_host(href) if href.lower().startswith(("http://", "https://")) else ""
        shown = {registered_domain(d) for d in _DOMAIN_IN_TEXT.findall(text[:LINK_TEXT_CHARS]) if looks_like_domain(d)}
        if href_host and shown and registered_domain(href_host) not in shown:
            mismatches += 1

    # Where the links really go: href targets for HTML mail (the URL list also holds URLs only shown as text).
    targets = {registered_domain(url_host(href)) for href, _ in summary.links} - {""} if summary else domains
    mentioned = brands_in(f"{record.get('subject') or ''}\n{(record.get('text') or '')[:TEXT_CHARS]}")
    not_linked = bool(targets) and any(not any(is_official(d, b) for d in targets) for b in mentioned)
    log_ranks = [ranks.log_rank(d) for d in domains] if ranks else []
    return {
        "n_urls": math.log1p(len(urls)),
        "n_link_domains": math.log1p(len(domains)),
        "ip_url": any(is_ip(h) for h in hosts),
        "punycode_url": any(is_punycode(h) for h in hosts),
        "confusable_url": any(has_confusable_letters(h) for h in hosts),
        "lookalike_url": any(lookalike_brand(h) for h in hosts),
        "shortener_url": any(d in SHORTENERS for d in domains),
        "url_with_credentials": any(_has_userinfo(u) for u in with_scheme),
        "http_share": sum(u.lower().startswith("http://") for u in with_scheme) / len(with_scheme)
        if with_scheme
        else 0.0,
        "max_url_length": math.log1p(max((len(u) for u in urls), default=0)),
        "max_subdomain_depth": max((h.count(".") for h in hosts if not is_ip(h)), default=0),
        "link_text_mismatch": math.log1p(mismatches),
        "brand_mentioned_not_linked": not_linked,
        "max_link_log_rank": max(log_ranks, default=0.0) if ranks else NAN,
        "unranked_link_share": sum(r > 6 for r in log_ranks) / len(log_ranks) if log_ranks else (0.0 if ranks else NAN),
        "has_html": bool(html),
        "html_form": bool(summary and summary.forms),
        "password_input": bool(summary and summary.password_inputs),
        "html_script": bool(summary and summary.scripts),
        "n_images": math.log1p(summary.images if summary else 0),
    }


def _has_userinfo(url: str) -> bool:
    try:
        return urlsplit(url).username is not None
    except ValueError:
        return False


def _attachment_features(attachments: list[dict]) -> dict[str, float]:
    extensions = set()
    for attachment in attachments:
        name = (attachment.get("filename") or "").lower()
        if "." in name:
            extensions.add(name.rsplit(".", 1)[1].strip())
        if "macroenabled" in (attachment.get("content_type") or "").lower():
            extensions.add("docm")
    return {
        "n_attachments": math.log1p(len(attachments)),
        "risky_attachment": bool(extensions & RISKY_EXTENSIONS),
        "html_attachment": bool(extensions & HTML_EXTENSIONS),
        "archive_attachment": bool(extensions & ARCHIVE_EXTENSIONS),
        "macro_attachment": bool(extensions & MACRO_EXTENSIONS),
    }


def _text_features(record: dict, reader: int = 1) -> dict[str, float]:
    if reader >= 2:
        from phish_triage.models.baselines import email_text

        text = email_text(record, reader)
    else:
        text = f"{record.get('subject') or ''}\n{(record.get('text') or '')[:TEXT_CHARS]}"
    return {
        "log_words": math.log1p(len(text.split())),
        "urgency_terms": math.log1p(len(URGENCY.findall(text))),
        "credential_terms": math.log1p(len(CREDENTIALS.findall(text))),
        "payment_terms": math.log1p(len(PAYMENT.findall(text))),
        "exclamations": math.log1p(text.count("!")),
        "recipient_address_in_body": PLACEHOLDER_ADDRESS in text.lower(),
    }
