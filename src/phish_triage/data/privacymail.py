"""The PrivacyMail newsletter dataset: a count-only look before it is used for anything.

    python -m phish_triage.data.privacymail    # or `make privacymail-counts`

About 500,000 commercial newsletters as `.eml` files, crowdsourced by PrivacyMail.info users over about two years
(Maass, Schwär and Hollick, "Towards transparency in email tracking", APF 2019; Zenodo record 6509751). Access was
granted on request; the raw data may not be shared, so the zip stays in data/private/privacymail/ (ignored by git)
and is read in place, one email at a time, never unzipped.

The zip holds one folder per website and, inside it, one folder per identity registered there. This prints only
counts and shares: emails, websites, years, languages, which headers exist, and the most common recipient domains
(the platform's own collection addresses, which would need masking like the other sources). No subject, body or
sender is printed.

Its first use was as a false-alarm test set (`evaluation/privacymail.py`): the deployed model flagged 76.5% of it.
`build` (`make data-privacymail`) then makes the `with_newsletters` split: `with_inbox` plus the same selected
English newsletters, split by website so the test websites are never seen in training (rules below). The dataset's
owner allows models trained on it to be used and published; only the newsletters themselves may not be shared.
"""

from __future__ import annotations

import argparse
import hashlib
import random
import re
import sys
import zipfile
from collections import Counter
from collections.abc import Iterator
from email.parser import BytesHeaderParser
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path

from phish_triage.data.parse import parse_email
from phish_triage.models.baselines import body_text

PRIVATE_DIR = Path("data/private/privacymail")
SOURCE = "privacymail"
FULL_PARSE_SAMPLE = 5_000  # language and HTML are measured on a random sample; header counts on every email
SEED = 20261103

# A few of the most frequent words per language: enough to tell the main languages apart in a count.
STOPWORDS = {
    "en": {"the", "and", "you", "your", "for", "with", "this", "our", "are", "from", "have", "more"},
    "de": {"und", "der", "die", "das", "sie", "ihr", "mit", "für", "nicht", "ist", "auf", "eine"},
    "fr": {"les", "des", "est", "pour", "vous", "une", "dans", "sur", "avec", "pas", "votre", "nous"},
    "es": {"los", "las", "para", "con", "una", "por", "del", "que", "más", "sus", "este", "nuestro"},
    "nl": {"het", "een", "van", "voor", "met", "niet", "zijn", "ook", "jouw", "onze", "wij", "deze"},
}
_WORD_RE = re.compile(r"[a-zäöüßéèêàçñ]+")


def find_zip(folder: Path = PRIVATE_DIR) -> Path:
    zips = sorted(folder.glob("*.zip"))
    if len(zips) != 1:
        raise SystemExit(f"expected one .zip in {folder}, found {len(zips)}")
    return zips[0]


def iter_eml(path: Path) -> Iterator[tuple[str, bytes]]:
    """(website folder, raw bytes) for every .eml in the zip, read without extracting it."""
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if info.is_dir() or not info.filename.lower().endswith(".eml"):
                continue
            parts = [p for p in info.filename.split("/") if p]
            website = parts[-3] if len(parts) >= 3 else parts[0]
            with archive.open(info) as f:
                yield website, f.read()


def language(text: str) -> str:
    words = _WORD_RE.findall(text.lower())
    scores = {lang: sum(w in stop for w in words) for lang, stop in STOPWORDS.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] >= 3 else "unknown"


def _year(date_header: str | None) -> str:
    try:
        return str(parsedate_to_datetime(date_header).year) if date_header else "none"
    except (TypeError, ValueError, IndexError, OverflowError):
        return "unparsable"


def count(path: Path, sample: int = FULL_PARSE_SAMPLE, seed: int = SEED) -> dict:
    headers_parser = BytesHeaderParser()
    rng = random.Random(seed)
    n, websites, years, recipients, has = 0, Counter(), Counter(), Counter(), Counter()
    reservoir: list[bytes] = []
    for website, raw in iter_eml(path):
        n += 1
        websites[website] += 1
        head = headers_parser.parsebytes(raw)
        years[_year(head.get("Date"))] += 1
        for name in ("DKIM-Signature", "Authentication-Results", "List-Unsubscribe", "Received"):
            has[name] += name in head
        for _, address in getaddresses(head.get_all("To") or []):
            if "@" in address:
                recipients[address.rpartition("@")[2].lower()] += 1
        # reservoir sample, so the full parse is on a uniform random sample in one pass
        if len(reservoir) < sample:
            reservoir.append(raw)
        elif (k := rng.randrange(n)) < sample:
            reservoir[k] = raw
    languages, html = Counter(), 0
    for raw in reservoir:
        record = parse_email(raw, source=SOURCE, label="legit", origin="privacymail").to_dict()
        html += bool(record.get("html"))
        languages[language(f"{record.get('subject') or ''} {body_text(record)}")] += 1
    return {
        "emails": n,
        "websites": len(websites),
        "emails_per_website": {
            "median": sorted(websites.values())[len(websites) // 2] if websites else 0,
            "largest": max(websites.values(), default=0),
        },
        "years": dict(sorted(years.items())),
        "header_share": {name: has[name] / max(n, 1) for name in sorted(has)},
        "top_recipient_domains": recipients.most_common(5),
        "sample": len(reservoir),
        "languages_in_sample": dict(languages.most_common()),
        "html_share_in_sample": html / max(len(reservoir), 1),
    }


NEWSLETTER_SPLIT = "with_newsletters"
MASKED = PRIVATE_DIR / "masked.jsonl.gz"
SPLIT_FILE = PRIVATE_DIR / "split.json"
PER_WEBSITE_TRAIN = 10  # set before the first run: variety of senders over volume, as with the inbox


def website_group(website: str) -> str:
    return hashlib.sha256(website.encode()).hexdigest()[:12]


def build_split(records: list[dict], base: dict[str, list[str]]) -> tuple[dict[str, list[str]], dict]:
    """`with_newsletters`: the `with_inbox` split plus the newsletters, websites assigned by size in the inbox's
    pattern (train, val, test, train, train). Train and val keep the first `PER_WEBSITE_TRAIN` of each website's
    selected emails (already in seeded random order); test keeps all of them (at most 25)."""
    from phish_triage.data.inbox import assign_senders

    by_site: dict[str, list[str]] = {}
    for r in records:
        by_site.setdefault(website_group(r["website"]), []).append(r["id"])
    part_of = assign_senders({g: len(ids) for g, ids in by_site.items()})
    parts: dict[str, list[str]] = {"train": [], "val": [], "test": []}
    for g in sorted(by_site):
        ids = by_site[g] if part_of[g] == "test" else by_site[g][:PER_WEBSITE_TRAIN]
        parts[part_of[g]] += ids
    split = {part: base[part] + parts[part] for part in ("train", "val", "test")}
    slices = {
        "privacymail_test": parts["test"],
        "website": {i: g for g, ids in by_site.items() if part_of[g] == "test" for i in ids},
    }
    return split, slices


def build() -> None:
    import gzip
    import json

    from phish_triage.data import inbox
    from phish_triage.evaluation.privacymail import select

    records, counts = select(find_zip())
    with gzip.open(MASKED, "wt", encoding="utf-8") as out:
        for r in records:
            out.write(json.dumps({k: v for k, v in r.items() if k != "website"}, ensure_ascii=False) + "\n")
    split, slices = build_split(records, inbox.load_split()[0])
    SPLIT_FILE.write_text(json.dumps({NEWSLETTER_SPLIT: split, "slices": slices}) + "\n")
    added = {part: len(split[part]) - len(inbox.load_split()[0][part]) for part in split}
    sites = len(set(slices["website"].values()))
    print(
        f"{counts['kept']} newsletters from {counts['websites with English mail']} websites; added {added}; "
        f"test: {len(slices['privacymail_test'])} emails from {sites} websites never in training",
        file=sys.stderr,
    )


def load_split() -> tuple[dict[str, list[str]], dict]:
    import json

    saved = json.loads(SPLIT_FILE.read_text())
    return saved[NEWSLETTER_SPLIT], saved["slices"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--zip", type=Path, default=None)
    parser.add_argument("--build", action="store_true", help="build the with_newsletters split")
    args = parser.parse_args(argv)
    if args.build:
        build()
        return 0
    result = count(args.zip or find_zip())
    for key, value in result.items():
        print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
