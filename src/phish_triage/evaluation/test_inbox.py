"""The private test inbox: how often the models flag real newsletter, shop and account mail.

    python -m phish_triage.evaluation.test_inbox    # or `make eval-test-inbox`

The inbox is a fresh Gmail account I subscribed to newsletters, shops and services, exported with Google Takeout
to data/private/test_inbox/test_inbox.mbox (ignored by git, never committed). The rules for it:

- **Never sent to an LLM.** This module scores with the local models only (the `random` split's models and
  DistilBERT int8); the analyst and the Claude classifier refuse `test_inbox` records in code as well.
- **Aggregates only.** The report (reports/test_inbox.md, .json) and everything printed are counts and rates.
  No subject, sender or body leaves the private folder.
- **Labels:** Gmail's folder is not proof. Every email outside Spam counts as legitimate; the Spam folder is only
  reported as "share flagged". Only flagged emails can change the false-alarm rate, so those are listed in
  data/private/test_inbox/review.csv for me to check by hand. If I mark one `phish` or `spam` in its `my_label`
  column, the next run reports the rates with it removed from the legitimate mail. Only the `id` and `my_label`
  columns are read back.

Each email gets one Gmail category, the most specific one it carries (Purchases is also labelled Updates).
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from collections.abc import Iterable
from pathlib import Path

import numpy as np

from phish_triage.data.loaders import _iter_mbox
from phish_triage.data.mask import mask_record
from phish_triage.data.parse import parse_email
from phish_triage.data.records import MASKED_RECORDS, read_records
from phish_triage.data.splits import SPLITS_DIR
from phish_triage.evaluation import metrics, predictions
from phish_triage.evaluation.cascade import run_cascade
from phish_triage.features.domains import default_ranks
from phish_triage.features.extract import matrix
from phish_triage.features.sender import check_sender, identity
from phish_triage.models.baselines import email_text, fit_all

PRIVATE_DIR = Path("data/private/test_inbox")
MBOX = PRIVATE_DIR / "test_inbox.mbox"
REVIEW_SHEET = PRIVATE_DIR / "review.csv"
REPORTS_DIR = Path("reports")
SOURCE = "test_inbox"
SPLIT = "random"  # the deployable models
DISTILBERT = "distilbert_head_int8"

# Most specific first. "Category Personal" is Gmail's Primary tab; an email in the inbox with no category is too.
CATEGORIES = (
    ("Spam", "spam"),
    ("Category Purchases", "purchases"),
    ("Category Promotions", "promotions"),
    ("Category Social", "social"),
    ("Category Forums", "forums"),
    ("Category Updates", "updates"),
    ("Category Personal", "primary"),
)
SKIPPED_LABELS = {"Sent", "Drafts", "Chat"}  # my own messages, not mail I received
CATEGORY_ORDER = ("primary", "updates", "promotions", "purchases", "social", "forums", "other")
MODELS = {
    "course": "Course setup (word TF-IDF + LR)",
    "text": "TF-IDF words + chars + LR",
    "features": "Trees on structured features",
    "stacked": "Trees on features + text score",
    "distilbert": "DistilBERT, ONNX int8",
    "cascade": "Cascade: stacked -> DistilBERT int8",
}
REVIEW_LABELS = {"", "legit", "phish", "spam"}
REVIEW_FIELDS = ("id", "category", "sender_domain", "subject", "flagged_by", "my_label", "my_note")
WARNING_TYPES = (  # sender-check warnings by kind; the text itself names domains, so it is never reported
    ("A lower Authentication-Results", "forged lower auth header"),
    ("looks like", "look-alike domain"),
    ("The display name says", "display-name brand mismatch"),
    ("Replies go to", "Reply-To elsewhere"),
    ("not among the top 1 million", "unranked sender domain"),
)


def gmail_category(labels_header: str | None) -> str | None:
    """One category per email from Takeout's X-Gmail-Labels header; None for messages I sent."""
    labels = {label.strip() for label in (labels_header or "").split(",") if label.strip()}
    if labels & SKIPPED_LABELS:
        return None
    for label, category in CATEGORIES:
        if label in labels:
            return category
    return "primary" if "Inbox" in labels else "other"


def load_inbox(path: Path = MBOX) -> tuple[list[dict], list[str], int]:
    """(parsed records, their categories, messages skipped). Nothing is printed or written here."""
    records, categories, skipped = [], [], 0
    for raw, origin in _iter_mbox(path, "mbox"):
        header_end = raw.find(b"\n\n")
        head = raw[: header_end if header_end >= 0 else len(raw)]
        labels = next(
            (
                line.split(b":", 1)[1].decode("utf-8", "replace")
                for line in head.splitlines()
                if line.lower().startswith(b"x-gmail-labels:")
            ),
            None,
        )
        category = gmail_category(labels)
        if category is None:
            skipped += 1
            continue
        label = "spam" if category == "spam" else "legit"
        records.append(parse_email(raw, source=SOURCE, label=label, origin=f"test_inbox.mbox{origin}").to_dict())
        categories.append(category)
    return records, categories, skipped


def warning_type(text: str) -> str:
    return next((kind for prefix, kind in WARNING_TYPES if prefix in text), "other")


def _share(flags: np.ndarray, n_bootstrap: int) -> dict:
    flags = np.asarray(flags, dtype=float)
    if not len(flags):
        return {"emails": 0}
    estimate = metrics.bootstrap(lambda _y, d: float(d.mean()), np.zeros(len(flags)), flags, n_bootstrap)
    return {
        "emails": len(flags),
        "flagged": int(flags.sum()),
        "share": estimate.value,
        "low": estimate.low,
        "high": estimate.high,
    }


def aggregate(
    categories: list[str],
    flags: dict[str, np.ndarray],
    sender_verdicts: list[str],
    sender_warnings: list[list[str]],
    recall_on_random: dict[str, float],
    review: dict[str, str] | None = None,
    ids: list[str] | None = None,
    n_bootstrap: int = metrics.N_BOOTSTRAP,
) -> dict:
    """Counts and rates only: everything here may be committed."""
    cats = np.array(categories)
    legit = cats != "spam"
    present = [c for c in CATEGORY_ORDER if (cats == c).any()]
    out: dict = {
        "emails": len(categories),
        "by_category": {c: int((cats == c).sum()) for c in (*present, "spam") if (cats == c).any()},
        "sender_check": {},
        "sender_warnings": {},
        "false_alarms": {},
        "spam_folder_flagged": {},
        "precision_at_1_in_100": {},
    }
    for c in (*present, "spam"):
        members = cats == c
        if not members.any():
            continue
        verdicts = Counter(v for v, m in zip(sender_verdicts, members, strict=True) if m)
        out["sender_check"][c] = {v: verdicts[v] / members.sum() for v in ("pass", "partial", "fail", "none")}
        kinds = Counter(
            kind
            for warnings, m in zip(sender_warnings, members, strict=True)
            if m
            for kind in {warning_type(w) for w in warnings}
        )
        out["sender_warnings"][c] = dict(sorted(kinds.items()))
    for model, f in flags.items():
        f = np.asarray(f)
        out["false_alarms"][model] = {"all": _share(f[legit], n_bootstrap)} | {
            c: _share(f[cats == c], n_bootstrap) for c in present
        }
        out["spam_folder_flagged"][model] = _share(f[cats == "spam"], n_bootstrap)
        fpr = out["false_alarms"][model]["all"].get("share")
        if model in recall_on_random and fpr is not None:
            out["precision_at_1_in_100"][model] = metrics.precision_at_prevalence(recall_on_random[model], fpr)
    if review and ids:
        marked = {i: lab for i, lab in review.items() if lab}
        not_legit = np.array([marked.get(i) in ("phish", "spam") for i in ids])
        kept = legit & ~not_legit
        out["review"] = {
            "marked": dict(sorted(Counter(marked.values()).items())),
            "removed_from_legitimate": int((legit & not_legit).sum()),
            "false_alarms": {m: _share(np.asarray(f)[kept], n_bootstrap) for m, f in flags.items()},
        }
    return out


def read_review(path: Path = REVIEW_SHEET) -> dict[str, str]:
    """Only `id` and `my_label`; the other columns are for me and are never read here."""
    if not path.exists():
        return {}
    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or not {"id", "my_label"} <= set(reader.fieldnames):
            raise SystemExit(f"{path}: the header row must have `id` and `my_label`")
        labels = {row["id"]: (row["my_label"] or "").strip().lower() for row in reader}
    bad = sorted({lab for lab in labels.values() if lab not in REVIEW_LABELS})
    if bad:
        raise SystemExit(f"{path}: my_label must be empty, legit, phish or spam (found {len(bad)} other values)")
    return labels


def write_review(records: list[dict], categories: list[str], flags: dict[str, np.ndarray], path: Path = REVIEW_SHEET):
    """The flagged emails outside Spam, for me to check by hand. Stays in the private folder; my labels are kept."""
    previous: dict[str, dict] = {}
    if path.exists():
        with path.open(newline="", encoding="utf-8-sig") as f:
            previous = {row["id"]: row for row in csv.DictReader(f)}
    rows = []
    for k, (record, category) in enumerate(zip(records, categories, strict=True)):
        flagged_by = [m for m, f in flags.items() if f[k]]
        if category == "spam" or not flagged_by:
            continue
        old = previous.get(record["id"], {})
        rows.append(
            {
                "id": record["id"],
                "category": category,
                "sender_domain": identity(record["headers"]).domain or "",
                "subject": record["subject"] or "",
                "flagged_by": " ".join(flagged_by),
                "my_label": old.get("my_label", ""),
                "my_note": old.get("my_note", ""),
            }
        )
    rows.sort(key=lambda r: (-len(r["flagged_by"].split()), r["category"], r["id"]))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=REVIEW_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def fit_models():
    """The `random` split's models, their validation thresholds (1% false alarms), the cascade's validation data,
    and each setup's recall on the `random` test (for precision at 1 in 100)."""
    splits = json.loads((SPLITS_DIR / "splits.json").read_text())[SPLIT]
    records = read_records(MASKED_RECORDS, {i for part in splits.values() for i in part})
    ranks = default_ranks()

    def part(which: str):
        members = splits[which]
        rows = [records[i] for i in members]
        return [email_text(r) for r in rows], matrix(rows, ranks), np.array([int(r["label"] == "phish") for r in rows])

    train, val, test = part("train"), part("val"), part("test")
    fitted = fit_all(*train, *val)
    val_scores, test_scores = fitted.scores(val[0], val[1]), fitted.scores(test[0], test[1])
    saved = predictions.load(SPLIT, DISTILBERT)
    by_id_val = dict(zip(saved.val_ids, saved.val_scores, strict=True))
    by_id_test = dict(zip(saved.test_ids, saved.test_scores, strict=True))
    val_scores["distilbert"] = np.array([by_id_val[i] for i in splits["val"]])
    test_scores["distilbert"] = np.array([by_id_test[i] for i in splits["test"]])
    thresholds = {m: metrics.threshold_at_fpr(val[2], val_scores[m], 0.01) for m in MODELS if m != "cascade"}
    recall = {m: float((test_scores[m][test[2] == 1] > thresholds[m]).mean()) for m in thresholds}
    cascade_val = (val[2], val_scores["stacked"])
    on_test = run_cascade([cascade_val], [test_scores["stacked"], test_scores["distilbert"]], thresholds["distilbert"])
    recall["cascade"] = float(on_test.decisions[test[2] == 1].mean())
    return fitted, ranks, thresholds, cascade_val, recall


def score_inbox(masked: list[dict], fitted, ranks, thresholds, cascade_val) -> tuple[dict[str, np.ndarray], list]:
    from phish_triage.models.train_transformer import ARTIFACTS_DIR
    from phish_triage.models.transformer import OnnxClassifier

    texts = [email_text(r) for r in masked]
    scores = fitted.scores(texts, matrix(masked, ranks))
    scores["distilbert"] = OnnxClassifier(ARTIFACTS_DIR / "distilbert" / "model.int8.onnx", threads=4).score(texts)
    flags = {m: (scores[m] > thresholds[m]).astype(int) for m in MODELS if m != "cascade"}
    cascade = run_cascade([cascade_val], [scores["stacked"], scores["distilbert"]], thresholds["distilbert"])
    flags["cascade"] = cascade.decisions.astype(int)
    return flags, cascade.shares(2)


def _pct(s: dict) -> str:
    if not s.get("emails"):
        return ""
    return f"{s['share']:.1%} [{s['low']:.1%}, {s['high']:.1%}] ({s['flagged']} of {s['emails']})"


def to_markdown(r: dict) -> str:
    cats = [c for c in r["by_category"] if c != "spam"]
    lines = [
        "# The private test inbox",
        "",
        "Generated by `make eval-test-inbox`. A fresh Gmail account subscribed to newsletters, shops and services, "
        "exported with Google Takeout. The emails are never committed and never sent to an LLM; only these "
        "aggregates leave the private folder. The models are the `random` split's, each with its validation "
        "threshold for 1% false alarms. Brackets are 95% bootstrap intervals.",
        "",
        f"{r['emails']:,} emails ({r['skipped']} I sent left out), {r['first_month']} to {r['last_month']}. Every "
        "email outside Spam counts as legitimate; Gmail's folder is not proof, so the flagged ones are listed for "
        "me to check by hand (see below).",
        "",
        "| Gmail category | Emails |",
        "|---|---:|",
        *[f"| {c} | {n:,} |" for c, n in r["by_category"].items()],
        "",
        "## False alarms on legitimate mail",
        "",
        "| Model | All legitimate | " + " | ".join(cats) + " | Precision @ 1 in 100 |",
        "|---|---|" + "---|" * len(cats) + "---:|",
    ]
    for m, name in MODELS.items():
        fa = r["false_alarms"][m]
        precision = r["precision_at_1_in_100"].get(m)
        cells = " | ".join(_pct(fa.get(c, {})) for c in cats)
        lines.append(f"| {name} | {_pct(fa['all'])} | {cells} | {precision:.3f} |")
    lines += [
        "",
        "Precision @ 1 in 100: of the emails flagged, the share that would be phishing if 1 email in 100 were, "
        "with the model catching phishing as on the `random` test and false alarms as on this inbox.",
        "",
        f"The cascade decided {r['cascade_shares'][0]:.1%} of these emails at stage 1 and "
        f"{r['cascade_shares'][1]:.1%} at stage 2.",
        "",
    ]
    if "spam" in r["by_category"]:
        lines += [
            "## The Spam folder",
            "",
            "Reported as a share flagged only: Gmail's Spam folder holds spam, maybe phishing, and maybe misfiled "
            "mail, and I don't label it.",
            "",
            "| Model | Flagged |",
            "|---|---|",
            *[f"| {name} | {_pct(r['spam_folder_flagged'][m])} |" for m, name in MODELS.items()],
            "",
        ]
    lines += [
        "## Sender check (Gmail's own SPF / DKIM / DMARC results)",
        "",
        "| Gmail category | Pass | Partial | Fail | None | Warnings (emails) |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for c, v in r["sender_check"].items():
        warnings = ", ".join(f"{k} {n}" for k, n in r["sender_warnings"].get(c, {}).items())
        lines.append(f"| {c} | {v['pass']:.1%} | {v['partial']:.1%} | {v['fail']:.1%} | {v['none']:.1%} | {warnings} |")
    lines += ["", "## My review of the flagged emails", ""]
    review = r.get("review")
    if not review or not review["marked"]:
        lines.append(f"Not reviewed yet: {r['flagged_for_review']} flagged emails are waiting in the private sheet.")
    else:
        marked = ", ".join(f"{k} {n}" for k, n in review["marked"].items())
        lines += [
            f"{sum(review['marked'].values())} of {r['flagged_for_review']} flagged emails reviewed ({marked}). "
            f"{review['removed_from_legitimate']} I marked phishing or spam are removed from the legitimate mail:",
            "",
            "| Model | False alarms after my review |",
            "|---|---|",
            *[f"| {name} | {_pct(review['false_alarms'][m])} |" for m, name in MODELS.items()],
        ]
    lines += [
        "",
        "Unflagged emails were not reviewed, so a phishing email Gmail delivered and every model missed would "
        "still count as legitimate here.",
        "",
    ]
    return "\n".join(lines)


def _months(records: Iterable[dict]) -> tuple[str, str]:
    months = sorted(r["date"][:7] for r in records if r.get("date"))
    return (months[0], months[-1]) if months else ("?", "?")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bootstrap", type=int, default=metrics.N_BOOTSTRAP)
    args = parser.parse_args(argv)
    if not MBOX.exists():
        raise SystemExit(f"{MBOX} is missing (see the module docstring)")
    records, categories, skipped = load_inbox()
    masked = [mask_record(r) for r in records]
    print(f"{len(records)} emails, {skipped} skipped; fitting the `{SPLIT}` models", file=sys.stderr)
    fitted, ranks, thresholds, cascade_val, recall = fit_models()
    flags, shares = score_inbox(masked, fitted, ranks, thresholds, cascade_val)
    checks = [check_sender(r, ranks) for r in records]
    flagged_for_review = write_review(records, categories, flags)
    ids = [r["id"] for r in records]
    result = aggregate(
        categories,
        flags,
        [c.verdict for c in checks],
        [list(c.warnings) for c in checks],
        recall,
        read_review(),
        ids,
        args.bootstrap,
    )
    first, last = _months(records)
    result |= {
        "skipped": skipped,
        "first_month": first,
        "last_month": last,
        "cascade_shares": shares,
        "flagged_for_review": flagged_for_review,
        "recall_on_random_test": recall,
    }
    REPORTS_DIR.mkdir(exist_ok=True)
    (REPORTS_DIR / "test_inbox.json").write_text(json.dumps(result, indent=1) + "\n")
    (REPORTS_DIR / "test_inbox.md").write_text(to_markdown(result))
    print(to_markdown(result))
    print(f"{flagged_for_review} flagged emails listed in {REVIEW_SHEET} (private)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
