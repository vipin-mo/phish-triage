"""Every dataset this project uses: where it comes from, its license, and how its files are labelled.

This registry is the single source of truth for `download.py`, `loaders.py` and `docs/DATA.md`.
Raw files are downloaded into `data/raw/<source name>/` and never committed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

NAZARIO_BASE = "https://monkey.org/~jose/phishing/"
SPAMASSASSIN_BASE = "https://spamassassin.apache.org/old/publiccorpus/"

# phishing_pot keeps changing (new samples, duplicate clean-ups), so every run uses one pinned commit.
PHISHING_POT_COMMIT = "80a486701223f31e5c641024d6e45f2663f1b2cb"  # main on 2026-10-30

# Public Apache mailing lists with human discussion and announcements, from different projects so no
# single community's style dominates. Each archive month is one mbox file from the lists.apache.org API.
APACHE_LISTS = (
    "announce@apache.org",
    "users@httpd.apache.org",
    "users@tomcat.apache.org",
    "user@cassandra.apache.org",
    "dev@community.apache.org",
)
APACHE_FIRST_MONTH = date(2015, 1, 1)
APACHE_LAST_MONTH = date(2026, 9, 1)


@dataclass(frozen=True)
class RemoteFile:
    url: str
    filename: str
    label: str  # "phish", "legit" or "spam"


@dataclass(frozen=True)
class Source:
    name: str
    description: str
    license: str
    homepage: str
    attribution: str
    fmt: str  # "mbox", "tar-maildir" (one message per tar member) or "tar-eml"
    files: tuple[RemoteFile, ...] = field(default_factory=tuple)
    # False when the server renders files on request (the bytes may differ between downloads), so a
    # checksum change is reported as a warning instead of an error.
    byte_stable: bool = True
    seconds_between_requests: float = 0.5


def _months(first: date, last: date) -> list[date]:
    months, current = [], first
    while current <= last:
        months.append(current)
        current = date(current.year + (current.month == 12), current.month % 12 + 1, 1)
    return months


def _apache_files() -> tuple[RemoteFile, ...]:
    files = []
    for address in APACHE_LISTS:
        name, domain = address.split("@")
        for month in _months(APACHE_FIRST_MONTH, APACHE_LAST_MONTH):
            ym = f"{month:%Y-%m}"
            files.append(
                RemoteFile(
                    url=f"https://lists.apache.org/api/mbox.lua?list={name}&domain={domain}&d={ym}",
                    filename=f"{address}/{ym}.mbox",
                    label="legit",
                )
            )
    return tuple(files)


NAZARIO_FILES = (
    "phishing0.mbox",
    "phishing1.mbox",
    "20051114.mbox",
    "phishing2.mbox",
    "phishing3.mbox",
    "private-phishing4.mbox",
    *(f"phishing-{year}" for year in range(2015, 2026)),
)

SPAMASSASSIN_FILES = (
    "20021010_easy_ham.tar.bz2",
    "20021010_hard_ham.tar.bz2",
    "20021010_spam.tar.bz2",
    "20030228_easy_ham.tar.bz2",
    "20030228_easy_ham_2.tar.bz2",
    "20030228_hard_ham.tar.bz2",
    "20030228_spam.tar.bz2",
    "20030228_spam_2.tar.bz2",
    "20050311_spam_2.tar.bz2",
)

SOURCES: dict[str, Source] = {
    s.name: s
    for s in (
        Source(
            name="nazario",
            description="Jose Nazario's phishing corpus: hand-classified phishing from one personal inbox, "
            "2004-2015 mboxes and one file per year 2015-2025.",
            license="CC-BY-4.0",
            homepage=NAZARIO_BASE,
            attribution="Jose Nazario, phishing corpus, https://monkey.org/~jose/phishing/",
            fmt="mbox",
            files=tuple(RemoteFile(NAZARIO_BASE + f, f, "phish") for f in NAZARIO_FILES),
        ),
        Source(
            name="phishing_pot",
            description="rf-peixoto/phishing_pot: real phishing .eml samples received by long-exposed "
            f"honeypot addresses, about 2022-2026. Pinned to commit {PHISHING_POT_COMMIT[:12]}.",
            license="CC BY-NC 4.0 (non-commercial use only)",
            homepage="https://github.com/rf-peixoto/phishing_pot",
            attribution="rf-peixoto, Phishing Pot, https://github.com/rf-peixoto/phishing_pot",
            fmt="tar-eml",
            files=(
                RemoteFile(
                    f"https://codeload.github.com/rf-peixoto/phishing_pot/tar.gz/{PHISHING_POT_COMMIT}",
                    f"phishing_pot-{PHISHING_POT_COMMIT[:12]}.tar.gz",
                    "phish",
                ),
            ),
        ),
        Source(
            name="apache",
            description="Public Apache Software Foundation mailing-list archives (lists.apache.org), "
            f"{len(APACHE_LISTS)} lists, every month {APACHE_FIRST_MONTH:%Y-%m} to {APACHE_LAST_MONTH:%Y-%m}.",
            license="Public mailing-list archives; no explicit license (research use, not redistributed)",
            homepage="https://lists.apache.org/",
            attribution="The Apache Software Foundation, public mailing-list archives",
            fmt="mbox",
            files=_apache_files(),
            byte_stable=False,
            seconds_between_requests=1.0,
        ),
        Source(
            name="spamassassin",
            description="SpamAssassin public corpus (mail from 2001-2002, released 2002-2005): legitimate mail "
            "(easy/hard ham) and spam. Used only for the old-era comparison and the leakage demo.",
            license="No explicit license; distributed for research by the SpamAssassin project",
            homepage=SPAMASSASSIN_BASE,
            attribution="The Apache SpamAssassin project, public corpus",
            fmt="tar-maildir",
            files=tuple(
                RemoteFile(SPAMASSASSIN_BASE + f, f, "spam" if "spam" in f else "legit") for f in SPAMASSASSIN_FILES
            ),
        ),
    )
}
