"""Domain helpers shared by the URL, header and sender features. Nothing here touches the network.

- The registered domain ("paypal.co.uk" for "login.paypal.co.uk") comes from tldextract's bundled public-suffix
  snapshot, so it is pinned by the package version and never downloaded at run time.
- Popularity comes from the pinned Tranco top-1M list (`data/raw/tranco/`), loaded once.
- Brands are a short hand-made list of the names phishing impersonates most, with their real domains.
"""

from __future__ import annotations

import csv
import ipaddress
import json
import math
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

import tldextract
from confusable_homoglyphs import confusables
from rapidfuzz.distance import Levenshtein

from phish_triage.data.sources import REFERENCE

TRANCO_PATH = Path("data/raw/tranco") / REFERENCE["tranco"].files[0].filename
UNRANKED_LOG_RANK = 6.5  # log10 rank given to domains outside the top 1M (log10(1M) = 6)

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # bundled snapshot only, no download

# Brand -> its real registered domains. Display names and link text are matched against the brand words.
BRANDS: dict[str, frozenset[str]] = {
    name: frozenset(domains)
    for name, domains in {
        "paypal": {"paypal.com", "paypal.me", "paypalobjects.com"},
        "microsoft": {
            "microsoft.com",
            "office.com",
            "office365.com",
            "live.com",
            "outlook.com",
            "microsoftonline.com",
            "sharepoint.com",
            "onmicrosoft.com",
            "hotmail.com",
            "msn.com",
            "onedrive.com",
        },
        "office 365": {"microsoft.com", "office.com", "office365.com", "microsoftonline.com", "outlook.com"},
        "outlook": {"microsoft.com", "outlook.com", "live.com", "office.com", "hotmail.com"},
        "onedrive": {"microsoft.com", "onedrive.com", "live.com", "sharepoint.com"},
        "apple": {"apple.com", "icloud.com", "me.com"},
        "icloud": {"apple.com", "icloud.com"},
        "amazon": {
            "amazon.com",
            "amazon.co.uk",
            "amazon.de",
            "amazon.ca",
            "amazon.in",
            "amazonses.com",
            "aws.amazon.com",
        },
        "google": {
            "google.com",
            "gmail.com",
            "googlemail.com",
            "youtube.com",
            "googleusercontent.com",
            "googleapis.com",
            "gstatic.com",
            "googlegroups.com",
        },
        "gmail": {"google.com", "gmail.com", "googlemail.com"},
        "netflix": {"netflix.com"},
        "facebook": {"facebook.com", "facebookmail.com", "meta.com", "fb.com"},
        "instagram": {"instagram.com", "facebookmail.com", "meta.com"},
        "whatsapp": {"whatsapp.com", "meta.com"},
        "linkedin": {"linkedin.com"},
        "dhl": {"dhl.com", "dhl.de"},
        "fedex": {"fedex.com"},
        "ups": {"ups.com"},
        "usps": {"usps.com"},
        "wells fargo": {"wellsfargo.com"},
        "chase": {"chase.com", "jpmorganchase.com"},
        "bank of america": {"bankofamerica.com", "bofa.com"},
        "citibank": {"citi.com", "citibank.com"},
        "hsbc": {"hsbc.com", "hsbc.co.uk"},
        "usaa": {"usaa.com"},
        "american express": {"americanexpress.com", "aexp.com"},
        "docusign": {"docusign.com", "docusign.net"},
        "dropbox": {"dropbox.com", "dropboxmail.com"},
        "adobe": {"adobe.com"},
        "ebay": {"ebay.com", "ebay.co.uk"},
        "yahoo": {"yahoo.com", "yahoo.co.uk"},
        "coinbase": {"coinbase.com"},
        "binance": {"binance.com"},
        "metamask": {"metamask.io"},
        "ledger": {"ledger.com"},
        "trust wallet": {"trustwallet.com"},
        "blockchain": {"blockchain.com"},
        "irs": {"irs.gov"},
        "zoom": {"zoom.us"},
        "spotify": {"spotify.com"},
        "steam": {"steampowered.com", "steamcommunity.com"},
    }.items()
}
_BRAND_RE = re.compile(r"\b(" + "|".join(re.escape(b) for b in sorted(BRANDS, key=len, reverse=True)) + r")\b", re.I)
# Single-word brand names compared with domain labels for look-alikes. Shorter names are common words ("chase",
# "apple", "steam"), so only names of 6+ letters are matched by edit distance.
_LOOKALIKE_TARGETS = sorted({b for b in BRANDS if " " not in b and len(b) >= 5})
_EDIT_DISTANCE_MIN_LENGTH = 6

SHORTENERS = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly",
        "cutt.ly",
        "shorturl.at",
        "tiny.cc",
        "rb.gy",
        "t.ly",
        "bl.ink",
        "short.io",
        "s.id",
        "v.gd",
        "lnkd.in",
        "qrco.de",
        "shorturl.me",
    }
)
FREE_MAIL = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "yahoo.com",
        "yahoo.co.uk",
        "hotmail.com",
        "outlook.com",
        "live.com",
        "msn.com",
        "aol.com",
        "icloud.com",
        "me.com",
        "mail.com",
        "gmx.com",
        "gmx.de",
        "gmx.net",
        "web.de",
        "yandex.com",
        "yandex.ru",
        "mail.ru",
        "protonmail.com",
        "proton.me",
        "zoho.com",
        "qq.com",
        "163.com",
        "126.com",
    }
)


@lru_cache(maxsize=200_000)
def registered_domain(host: str) -> str:
    """ "login.paypal.co.uk" -> "paypal.co.uk". IP addresses and single labels come back unchanged."""
    host = host.strip().strip(".").lower()
    if not host or is_ip(host):
        return host
    parts = _EXTRACT(host)
    if parts.suffix:
        return f"{parts.domain}.{parts.suffix}" if parts.domain else parts.suffix
    labels = host.split(".")  # not a public suffix (e.g. reserved ".test"): use the last two labels
    return ".".join(labels[-2:])


def looks_like_domain(token: str) -> bool:
    """True for "paypal.com" or "login.example.co.uk"; false for "John.Smith" (no public suffix)."""
    parts = _EXTRACT(token.strip(".").lower())
    return bool(parts.domain and parts.suffix)


def url_host(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        url = "http://" + url
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def address_domain(address: str) -> str:
    return address.rpartition("@")[2].strip().strip(">").lower() if "@" in address else ""


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def is_punycode(host: str) -> bool:
    return any(label.startswith("xn--") for label in host.split("."))


def has_confusable_letters(host: str) -> bool:
    """Non-ASCII letters that look like Latin ones ("pаypal" with a Cyrillic "а"), after decoding punycode."""
    try:
        decoded = host.encode().decode("idna") if is_punycode(host) else host
    except UnicodeError:
        return True
    return not decoded.isascii() and bool(confusables.is_dangerous(decoded))


def brands_in(text: str) -> set[str]:
    return {match.lower() for match in _BRAND_RE.findall(text or "")}


def is_official(domain: str, brand: str) -> bool:
    return registered_domain(domain) in _official_domains()[brand]


@lru_cache(maxsize=1)
def _official_domains() -> dict[str, frozenset[str]]:
    return {brand: frozenset(registered_domain(d) for d in domains) for brand, domains in BRANDS.items()}


def lookalike_brand(host: str) -> str | None:
    """The brand a host imitates without belonging to it, or None.

    Caught: a brand name as a word of someone else's domain ("paypal-secure.com", "paypal.com.evil.test"), or a
    word of the domain one or two letters away from a longer brand name ("paypa1.com", "micros0ft-support.net"). Only
    substitutions and insertions count, because deleting a letter often gives a real word ("icloud" -> "cloud").
    """
    host = host.lower()
    if is_ip(host):
        return None
    domain = registered_domain(host)
    if any(is_official(domain, brand) for brand in _LOOKALIKE_TARGETS):
        return None
    words = set(re.split(r"[.-]", host))
    label_words = domain.split(".")[0].split("-")
    for brand in _LOOKALIKE_TARGETS:
        if brand in words:
            return brand
        if len(brand) >= _EDIT_DISTANCE_MIN_LENGTH and any(_close(word, brand) for word in label_words):
            return brand
    return None


def _close(word: str, brand: str) -> bool:
    if len(word) < len(brand):
        return False
    return word.startswith(brand) or 0 < Levenshtein.distance(word, brand) <= (1 if len(brand) < 8 else 2)


class DomainRanks:
    """Tranco rank lookup by registered domain."""

    def __init__(self, ranks: dict[str, int]):
        self.ranks = ranks

    @classmethod
    def load(cls, path: Path = TRANCO_PATH, limit: int | None = None) -> DomainRanks:
        ranks: dict[str, int] = {}
        with path.open(newline="") as f:
            for rank, domain in csv.reader(f):
                if limit and int(rank) > limit:
                    break
                ranks.setdefault(registered_domain(domain), int(rank))
        return cls(ranks)

    def save(self, path: Path) -> None:
        """The finished lookup (registered domain -> rank), so a cold start doesn't run tldextract on 1M rows."""
        path.write_text(json.dumps(self.ranks, separators=(",", ":")))

    @classmethod
    def load_saved(cls, path: Path) -> DomainRanks:
        return cls(json.loads(path.read_text()))

    def log_rank(self, domain: str) -> float:
        """log10 of the domain's rank; `UNRANKED_LOG_RANK` when it is not in the list."""
        rank = self.ranks.get(registered_domain(domain))
        return math.log10(rank) if rank else UNRANKED_LOG_RANK


@lru_cache(maxsize=1)
def default_ranks() -> DomainRanks:
    return DomainRanks.load()
