"""False alarms on commercial newsletters from many senders: the PrivacyMail dataset as a test set.

    python -m phish_triage.evaluation.privacymail    # or `make eval-privacymail` (needs the `with_inbox` bundle)

My test inbox has 26 test senders, so its 4.0% false-alarm rate rests on few companies. PrivacyMail
(`data/privacymail.py`) has about 500,000 newsletters from 1,423 websites, collected 2019–2022. The rules, set
before the first run:

- **English only** (the models were trained on English), by a stopword count on the visible text.
- **Duplicates removed within each website** (the same issue reached several of the platform's identities), on the
  visible text without addresses, links and numbers.
- **At most 25 emails per website**, read in a seeded random order, so a few large senders can't dominate.
- **Every email counts as legitimate:** they are newsletters from sites the platform subscribed to.
- **The deployed model is measured as it runs:** the bundle, one email at a time (`service/scanner.py`), after
  the same masking as training. The `random` split's public-data models are shown next to it for comparison.
  The deployed model was then the `with_inbox` bundle, so that is the one measured here: the `with_newsletters`
  bundle that replaced it is trained on part of this set, so its numbers come from the websites held out of its
  training (reports/with_inbox.md, checked one email at a time in reports/bundle.md).
- **The main number** is the deployed cascade's false-alarm rate, per email and averaged per website. Above 5% (the
  gate's limit on my inbox), it is the deployed model's main gap.

Only aggregates are written (reports/privacymail.md, .json): no website, sender, subject or body. The dataset may
not be shared, and it is never sent to an LLM (the analyst and the Claude classifier refuse `privacymail`).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
import time
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

from phish_triage.data.mask import mask_record
from phish_triage.data.parse import parse_email
from phish_triage.data.privacymail import SOURCE, find_zip, language
from phish_triage.evaluation.test_inbox import MODELS, fit_models, fmt_share, score_inbox, share
from phish_triage.features.sender import WARNING_SENTENCES
from phish_triage.models.baselines import body_text

REPORTS_DIR = Path("reports")
SEED = 20261104
PER_WEBSITE = 25
MAX_READS_PER_WEBSITE = 200  # stop looking for English, non-duplicate emails after this many
GATE_LIMIT = 0.05
_NOISE_RE = re.compile(r"\S+@\S+|https?://\S+|www\.\S+|\d+")
KIND_OF = {sentence: kind for kind, sentence in WARNING_SENTENCES.items()}  # the scanner returns the sentences


def website_of(name: str) -> str:
    parts = [p for p in name.split("/") if p]
    return parts[-3] if len(parts) >= 3 else parts[0]


def fingerprint(record: dict) -> str:
    """The visible text without addresses, links and numbers, which differ between identities."""
    text = f"{record.get('subject') or ''} {body_text(record)}".lower()
    return hashlib.sha256(" ".join(_NOISE_RE.sub(" ", text).split()).encode()).hexdigest()


def select(path: Path, per_website: int = PER_WEBSITE, seed: int = SEED) -> tuple[list[dict], dict]:
    """(masked records, counts). Reads only as many emails per website as it needs."""
    with zipfile.ZipFile(path) as archive:
        names: defaultdict[str, list[str]] = defaultdict(list)
        for info in archive.infolist():
            if not info.is_dir() and info.filename.lower().endswith(".eml"):
                names[website_of(info.filename)].append(info.filename)
        records, counts = [], Counter()
        for website in sorted(names):
            order = sorted(names[website])
            random.Random(f"{seed}-{website}").shuffle(order)
            seen, kept = set(), 0
            for name in order[:MAX_READS_PER_WEBSITE]:
                record = parse_email(archive.read(name), source=SOURCE, label="legit", origin="privacymail").to_dict()
                counts["read"] += 1
                if language(f"{record.get('subject') or ''} {body_text(record)}") != "en":
                    counts["not English"] += 1
                    continue
                key = fingerprint(record)
                if key in seen:
                    counts["duplicate"] += 1
                    continue
                seen.add(key)
                records.append(mask_record(record) | {"website": website})
                kept += 1
                if kept == per_website:
                    break
            counts["websites with English mail"] += kept > 0
    counts["websites"] = len(names)
    counts["kept"] = len(records)
    return records, dict(counts)


def deployed_flags(records: list[dict]) -> tuple[dict[str, np.ndarray], dict]:
    """The bundle, one email at a time, as the service runs it."""
    from phish_triage.data.inbox import SPLIT
    from phish_triage.service.bundle import latest
    from phish_triage.service.scanner import Scanner

    scanner = Scanner(latest(split=SPLIT), threads=4)
    results = [scanner.scan_record(r) for r in records]
    flags = {
        "cascade": np.array([r.cascade_phish for r in results], dtype=int),
        "review": np.array([r.verdict == "review" for r in results], dtype=int),
    }
    detail = {
        "version": scanner.version,
        "stage_shares": dict(Counter(r.stage for r in results)),
        "sender": dict(Counter(r.sender["verdict"] for r in results)),
        "warnings": Counter(KIND_OF[w] for r in results for w in r.sender["warnings"]),
    }
    return flags, detail


def per_website(flags: np.ndarray, websites: list[str]) -> float:
    groups = np.array(websites)
    return float(np.mean([flags[groups == w].mean() for w in np.unique(groups)]))


def measure(records: list[dict], n_bootstrap: int) -> dict:
    websites = [r["website"] for r in records]
    years = [str(r.get("date") or "")[:4] or "none" for r in records]
    out: dict = {"emails": len(records), "websites": len(set(websites)), "years": dict(sorted(Counter(years).items()))}

    deployed, detail = deployed_flags(records)
    out["deployed"] = {
        "version": detail["version"],
        "false_alarms": share(deployed["cascade"], n_bootstrap),
        "per_website": per_website(deployed["cascade"], websites),
        "sent_to_review": share(deployed["review"], n_bootstrap),
        "stage_shares": {k: v / len(records) for k, v in detail["stage_shares"].items()},
        "by_year": {
            y: share(deployed["cascade"][np.array(years) == y], n_bootstrap) for y in sorted(set(years)) if y != "none"
        },
    }
    out["sender_check"] = {k: v / len(records) for k, v in sorted(detail["sender"].items())}
    out["sender_warnings"] = {k: v / len(records) for k, v in detail["warnings"].most_common()}

    fitted, ranks, thresholds, cascade_val, _ = fit_models()
    public, _ = score_inbox(records, fitted, ranks, thresholds, cascade_val)
    out["public_only"] = {
        m: {"false_alarms": share(f, n_bootstrap), "per_website": per_website(f, websites)} for m, f in public.items()
    }
    return out


def to_markdown(r: dict, counts: dict) -> str:
    d = r["deployed"]
    years = r["years"]
    span = [y for y in years if y != "none"]
    rate = d["false_alarms"]["share"]
    lines = [
        "# PrivacyMail: false alarms on commercial newsletters from many senders",
        "",
        "Generated by `make eval-privacymail`. Newsletters crowdsourced by PrivacyMail.info users (Maass, Schwär and "
        "Hollick, APF 2019; Zenodo record 6509751), used here as a test set: every email counts as legitimate. The "
        "raw data may not be shared, so only aggregates are here, and it is never sent to an LLM. The rules are in "
        "`evaluation/privacymail.py`. Brackets are 95% bootstrap intervals.",
        "",
        f"{r['emails']:,} English emails from {r['websites']:,} websites ({span[0]}–{span[-1]}), at most "
        f"{PER_WEBSITE} per website after removing duplicates within each website. Read {counts['read']:,} emails to "
        f"find them: {counts.get('not English', 0):,} not English, {counts.get('duplicate', 0):,} duplicates.",
        "",
        "## The model deployed at the time",
        "",
        f"The bundle `{d['version']}`, one email at a time, as the service runs it. It was replaced by the "
        "`with_newsletters` bundle, trained with part of this set; that one is measured on websites held out of its "
        "training in reports/with_inbox.md.",
        "",
        "| | |",
        "|---|---|",
        f"| False alarms | {fmt_share(d['false_alarms'])} |",
        f"| Averaged per website | {d['per_website']:.1%} |",
        f"| Sent to review (little-text rule) | {fmt_share(d['sent_to_review'])} |",
        "| Decided by stage | " + ", ".join(f"{k} {v:.1%}" for k, v in sorted(d["stage_shares"].items())) + " |",
        "",
        f"Against the {GATE_LIMIT:.0%} limit the gate sets on my inbox: "
        f"{'above it, the gap that led to the `with_newsletters` retrain' if rate > GATE_LIMIT else 'within it'}.",
        "",
        "| Year | False alarms |",
        "|---|---|",
        *[f"| {y} | {fmt_share(s)} |" for y, s in d["by_year"].items()],
        "",
        "## Compared with the public-data models",
        "",
        "The `random` split's models (trained on public data only), each at its validation threshold for 1% false "
        "alarms.",
        "",
        "| Model | False alarms | Averaged per website |",
        "|---|---|---:|",
        *[
            f"| {MODELS[m]} | {fmt_share(v['false_alarms'])} | {v['per_website']:.1%} |"
            for m, v in r["public_only"].items()
        ],
        "",
        "## Sender check",
        "",
        "Results the receiving server wrote, as the newsletters arrived at PrivacyMail's own mail server.",
        "",
        "| Verdict | Share |",
        "|---|---:|",
        *[f"| {k} | {v:.1%} |" for k, v in r["sender_check"].items()],
        "",
        "| Warning | Share of emails |",
        "|---|---:|",
        *[f"| {k} | {v:.1%} |" for k, v in r["sender_warnings"].items()],
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    from phish_triage.evaluation import metrics

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--zip", type=Path, default=None)
    parser.add_argument("--bootstrap", type=int, default=metrics.N_BOOTSTRAP)
    args = parser.parse_args(argv)
    started = time.perf_counter()
    records, counts = select(args.zip or find_zip())
    print(f"selected {len(records)} emails from {counts['websites']} websites: {counts}", file=sys.stderr)
    result = measure(records, args.bootstrap)
    result["selection"] = counts
    REPORTS_DIR.mkdir(exist_ok=True)
    (REPORTS_DIR / "privacymail.json").write_text(json.dumps(result, indent=1) + "\n")
    (REPORTS_DIR / "privacymail.md").write_text(to_markdown(result, counts))
    print(to_markdown(result, counts))
    print(f"took {time.perf_counter() - started:.0f} s", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
