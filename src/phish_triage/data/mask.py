"""Remove the fingerprints that tell a model *which dataset* an email came from rather than whether it is phishing.

Every source was collected by a different inbox, and the receiving side leaves marks that have nothing to do with
the sender: Microsoft 365 adds dozens of `X-MS-*` headers to almost every phishing_pot message, the Apache archive
adds `List-*` headers, a subject tag and an unsubscribe footer, and Nazario's mail client adds `Status` and
`X-Keywords`. A model trained on raw records can score near 100% from those alone (see `audit.py`).

The same rules are applied to every source, so masking itself doesn't create a new difference between them:

- keep only headers the sender writes (`SENDER_HEADERS`), in one fixed order (Microsoft 365 reorders headers, so
  the original order identifies the source); drop everything added on the receiving side;
- move the topmost `Authentication-Results` (the one the receiving server wrote) out of the headers into a separate
  `auth` field, normalized to its `spf=`/`dkim=`/`dmarc=` results without the server name. Which results exist at
  all depends on the collecting server (0% to 99.7% coverage per source), so a model trained on this data would
  learn the source from it. The sender check uses `auth` as rules, not as a learned feature;
- for mail delivered through a mailing list, drop what the list software adds: the subject tag, a `Reply-To` that
  points back to the list, and the unsubscribe footer;
- replace recipient addresses, and the collection inboxes' names and domains, with neutral placeholders;
- replace the legitimate source's own names (`apache`, `tomcat`, ...) with "project". They are this dataset's
  version of the `enron` that leaked the label in my course project.

The record's `date` is kept: it is used to build the splits, not as a model feature.
"""

from __future__ import annotations

import re
from email.utils import getaddresses

PLACEHOLDER_ADDRESS = "user@example.com"
PLACEHOLDER_DOMAIN = "example.com"
PLACEHOLDER_NAME = "user"

# Headers written by the sender (or the sender's own mail server), in the fixed order the masked record uses.
# Everything else is dropped. `Return-Path` and `Sender` are left out on purpose: mailing lists rewrite both, so in
# this data they describe the list, not the sender. `Message-ID`, `In-Reply-To` and `References` are left out
# because their domains name the infrastructure: Apache's own servers for much of the legitimate mail, and the
# receiving Microsoft 365 servers for phishing that arrived without one (leakage audit AUC 0.92 on its own).
SENDER_HEADERS = (
    "From",
    "Reply-To",
    "To",
    "Cc",
    "Subject",
    "Date",
    "MIME-Version",
    "Content-Type",
    "Content-Transfer-Encoding",
    "Content-Language",
    "X-Mailer",
    "User-Agent",
    "X-Priority",
    "X-MSMail-Priority",
    "Importance",
    "DKIM-Signature",
)
_HEADER_ORDER = {name.lower(): (i, name) for i, name in enumerate(SENDER_HEADERS)}
RECIPIENT_HEADERS = frozenset({"to", "cc", "delivered-to", "x-original-to", "envelope-to", "x-envelope-to"})
LIST_HEADERS = frozenset({"list-id", "list-post", "mailing-list", "list-unsubscribe", "list-help"})

# The collection inboxes behind each source, found by counting recipient headers per source (docs/DATA.md).
# Replaced, with any subdomain, in every field of every source.
COLLECTOR_DOMAINS = (
    "monkey.org",  # Nazario
    "ponee.io",  # Apache archive
    "taint.org",  # SpamAssassin
    "netnoteinc.com",
    "jmason.org",
)
COLLECTOR_ADDRESSES = ("phishing@pot",)  # phishing_pot's own redaction of the honeypot address
COLLECTOR_NAMES = ("jose", "yyyy", "zzzz")  # Nazario's first name and SpamAssassin's redaction markers
SOURCE_NAMES = ("apache", "tomcat", "cassandra", "httpd")  # the Apache lists' own names
PLACEHOLDER_PROJECT = "project"

_DOMAIN_RE = re.compile(
    r"(?<![\w.-])(?:[\w-]+\.)*(?:" + "|".join(re.escape(d) for d in COLLECTOR_DOMAINS) + r")(?![\w-]|\.\w)",
    re.IGNORECASE,
)
_NAME_RE = re.compile(r"\b(?:" + "|".join(COLLECTOR_NAMES) + r")\b", re.IGNORECASE)
_SOURCE_NAME_RE = re.compile(r"(?<![^\W_])(?:" + "|".join(SOURCE_NAMES) + r")(?![^\W_])", re.IGNORECASE)
_AUTH_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
_DKIM_TAG_RE = re.compile(r"\b([ds])\s*=\s*([^;\s]+)")
_SUBJECT_TAG_RE = re.compile(r"^((?:\s*(?:re|fwd?|aw|sv)\s*:)*\s*)\[([^\]]{1,60})\]\s*", re.IGNORECASE)
_LIST_ID_RE = re.compile(r"<([^>]+)>")
_MAILTO_RE = re.compile(r"mailto:([^>\s]+)", re.IGNORECASE)

# Lines that mailing-list software appends, also when quoted inside a reply ("> To unsubscribe, ...").
_FOOTER_RES = (
    re.compile(r"^[> \t]*-{20,}[ \t]*\r?\n(?=[> \t]*To unsubscribe)", re.MULTILINE),
    re.compile(r"^[> \t]*To unsubscribe,? e-mail:.*(?:\r?\n|$)", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^[> \t]*For additional commands,? e-mail:.*(?:\r?\n|$)", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^[> \t]*\S*/mailman/listinfo/\S*[ \t]*(?:\r?\n|$)", re.MULTILINE | re.IGNORECASE),
)


def mask_record(record: dict) -> dict:
    """Return a masked copy of one unified record (see `parse.EmailRecord`)."""
    raw_headers: list[tuple[str, str]] = [tuple(h) for h in record["headers"]]
    names = {name.lower() for name, _ in raw_headers}
    is_list_mail = bool(names & LIST_HEADERS)
    list_names, list_addresses = _list_identity(raw_headers) if is_list_mail else (set(), set())
    replace = _replacer(_recipient_addresses(raw_headers))

    headers: list[tuple[int, str, str]] = []
    for name, value in raw_headers:
        key = name.lower()
        if key not in _HEADER_ORDER:
            continue
        if key == "subject" and is_list_mail:
            value = strip_list_tag(value, list_names)
        elif key == "reply-to" and is_list_mail and _addresses(value) <= list_addresses:
            continue
        elif key in ("to", "cc"):
            value = PLACEHOLDER_ADDRESS if _addresses(value) else value
        elif key == "dkim-signature":
            value = "; ".join(f"{tag}={val}" for tag, val in _DKIM_TAG_RE.findall(value))
        position, canonical = _HEADER_ORDER[key]
        headers.append((position, canonical, replace(value)))
    headers.sort(key=lambda h: h[0])  # stable: repeated headers (several DKIM signatures) keep their order

    subject = record["subject"] or ""
    if is_list_mail:
        subject = strip_list_tag(subject, list_names)
    return {
        **record,
        "headers": [(name, value) for _, name, value in headers],
        "auth": auth_results(raw_headers),
        "subject": replace(subject),
        "text": replace(strip_list_footer(record["text"] or "")),
        "html": replace(strip_list_footer(record["html"] or "")),
        "urls": [replace(url) for url in record["urls"]],
        "attachments": [
            {**a, "filename": replace(a["filename"]) if a["filename"] else None} for a in record["attachments"]
        ],
    }


def auth_results(headers: list[tuple[str, str]]) -> str | None:
    """Normalized results from the topmost Authentication-Results header, e.g. "spf=pass dkim=fail dmarc=none".

    Only the topmost header is trusted: it is the one the final receiving server wrote. Lower ones may have been
    inserted by the sender (threat model, rule 14). The server name is dropped because it identifies the collector.
    """
    value = next((v for k, v in headers if k.lower() == "authentication-results"), None)
    if value is None:
        return None
    found: dict[str, str] = {}
    for method, result in _AUTH_RESULT_RE.findall(value):
        found.setdefault(method.lower(), result.lower())
    return " ".join(f"{m}={found[m]}" for m in ("spf", "dkim", "dmarc") if m in found) or "none"


def strip_list_tag(subject: str, list_names: set[str]) -> str:
    """Remove a leading "[users@httpd]"-style tag that list software adds. "[Action Required]" stays."""
    match = _SUBJECT_TAG_RE.match(subject)
    if not match:
        return subject
    tag = match.group(2).strip().lower()
    if "@" in tag or tag in list_names:
        return match.group(1) + subject[match.end() :]
    return subject


def strip_list_footer(text: str) -> str:
    for pattern in _FOOTER_RES:
        text = pattern.sub("", text)
    return text


def _replacer(recipients: set[str]):
    addresses = sorted(recipients | set(COLLECTOR_ADDRESSES), key=len, reverse=True)
    address_re = re.compile("|".join(re.escape(a) for a in addresses), re.IGNORECASE) if addresses else None

    def replace(value: str) -> str:
        if address_re is not None:
            value = address_re.sub(PLACEHOLDER_ADDRESS, value)
        value = _DOMAIN_RE.sub(PLACEHOLDER_DOMAIN, value)
        value = _NAME_RE.sub(PLACEHOLDER_NAME, value)
        return _SOURCE_NAME_RE.sub(PLACEHOLDER_PROJECT, value)

    return replace


def _addresses(value: str) -> set[str]:
    return {address.lower() for _, address in getaddresses([value]) if "@" in address}


def _recipient_addresses(headers: list[tuple[str, str]]) -> set[str]:
    found: set[str] = set()
    for name, value in headers:
        if name.lower() in RECIPIENT_HEADERS:
            found |= _addresses(value)
    return found


def _list_identity(headers: list[tuple[str, str]]) -> tuple[set[str], set[str]]:
    """Names a list uses in subject tags ("users", "ilug") and the list's own addresses."""
    names, addresses = set(), set()
    for name, value in headers:
        key = name.lower()
        if key == "list-id" and (match := _LIST_ID_RE.search(value)):
            names.add(match.group(1).split(".")[0].lower())
        elif key in ("list-post", "mailing-list"):
            for address in _MAILTO_RE.findall(value) + re.findall(r"[\w.+-]+@[\w.-]+", value):
                addresses.add(address.lower().rstrip(";,"))
                names.add(address.split("@")[0].lower())
    return names, addresses
