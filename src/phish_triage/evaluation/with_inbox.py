"""Before and after: the models trained on public data only, and with part of my private test inbox.

    python -m phish_triage.evaluation.with_inbox    # or `make eval-with-inbox` (after `make train-with-inbox`)

"Before" is the `random` split's models; "after" is the `with_inbox` split's (`random` plus part of the inbox and
2026 phishing, split by sender; see `data/inbox.py`). Each model's threshold is chosen on its own validation
data for 1% false alarms. Both are measured on:

- the public `random` test (does adding the inbox cost phishing recall?);
- the inbox's test senders, which neither model saw (false alarms per email, and averaged per sender);
- the 2026 phishing test emails (newest phishing; neither model saw these);
- the Spam folder (share flagged; it is not labelled).

**Date-word shortcut check.** The inbox is late 2026, so a model could learn "2026" or "November" as legitimate.
Removing years, month and weekday names from the test text must not change the inbox false-alarm rate or the
2026 phishing recall of the "after" models by more than 2 percentage points (rule set before the first run).

Local models only, never an LLM. Only counts and rates are written (reports/with_inbox.md, .json).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import numpy as np

from phish_triage.data import inbox
from phish_triage.data.splits import SPLITS_DIR
from phish_triage.evaluation import metrics, predictions
from phish_triage.evaluation.cascade import run_cascade
from phish_triage.evaluation.test_inbox import MODELS, fmt_share, share
from phish_triage.features.domains import default_ranks
from phish_triage.features.extract import matrix
from phish_triage.models.baselines import email_text, fit_all

REPORTS_DIR = Path("reports")
ARTIFACTS_DIR = Path("artifacts")
SETUPS = {"before": "random", "after": inbox.SPLIT}
DISTILBERT = "distilbert_head_int8"
SHORTCUT_POINTS = 0.02
# Years, month and weekday names, as whole words. No nested repeats, so it can't backtrack.
DATE_WORDS = re.compile(
    r"\b(?:20[0-3]\d|jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sept?(?:ember)?"
    r"|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?|mon(?:day)?|tue(?:s|sday)?|wed(?:nesday)?|thu(?:rs|rsday)?"
    r"|fri(?:day)?|sat(?:urday)?|sun(?:day)?)\b",
    re.IGNORECASE,
)


def without_dates(text: str) -> str:
    return DATE_WORDS.sub(" ", text)


def _distilbert(split: str, val_ids: list[str], eval_ids: list[str], records: dict, texts: dict) -> tuple:
    """Validation and evaluation scores: saved predictions where they exist, the exported int8 model otherwise."""
    from phish_triage.models.transformer import OnnxClassifier

    saved = predictions.load(split, DISTILBERT)
    known = dict(zip(saved.val_ids, saved.val_scores, strict=True)) | dict(
        zip(saved.test_ids, saved.test_scores, strict=True)
    )
    missing = [i for i in eval_ids if i not in known]
    folder = "distilbert" if split == "random" else f"distilbert_{split}"
    classifier = OnnxClassifier(ARTIFACTS_DIR / folder / "model.int8.onnx", threads=4)
    if missing:
        known |= dict(zip(missing, classifier.score([texts[i] for i in missing]), strict=True))
    return np.array([known[i] for i in val_ids]), np.array([known[i] for i in eval_ids]), classifier


def evaluate_setup(split: dict, eval_ids: list[str], records: dict, ranks, texts: dict, features: dict, name: str):
    """Flags on `eval_ids` for every model, and the date-word check's flags (texts without date words)."""

    def part(which: str):
        ids = split[which]
        return (
            [texts[i] for i in ids],
            np.array([features[i] for i in ids]),
            np.array([int(records[i]["label"] == "phish") for i in ids]),
        )

    train, val = part("train"), part("val")
    fitted = fit_all(*train, *val)
    val_scores = fitted.scores(val[0], val[1])
    eval_texts, eval_features = [texts[i] for i in eval_ids], np.array([features[i] for i in eval_ids])
    plain = [without_dates(t) for t in eval_texts]
    scores, dateless = fitted.scores(eval_texts, eval_features), fitted.scores(plain, eval_features)
    val_scores["distilbert"], scores["distilbert"], classifier = _distilbert(
        SETUPS[name], split["val"], eval_ids, records, texts
    )
    dateless["distilbert"] = classifier.score(plain) if name == "after" else scores["distilbert"]
    thresholds = {m: metrics.threshold_at_fpr(val[2], val_scores[m], 0.01) for m in MODELS if m != "cascade"}
    cascade_val = [(val[2], val_scores["stacked"])]

    def flags_for(s: dict) -> dict[str, np.ndarray]:
        out = {m: (s[m] > thresholds[m]).astype(int) for m in thresholds}
        out["cascade"] = run_cascade(cascade_val, [s["stacked"], s["distilbert"]], thresholds["distilbert"]).decisions
        return out

    return flags_for(scores), flags_for(dateless)


def measure(flags: dict[str, np.ndarray], eval_ids: list[str], records: dict, slices: dict, n_bootstrap: int) -> dict:
    position = {i: k for k, i in enumerate(eval_ids)}

    def sub(name: str) -> np.ndarray:
        return np.array([position[i] for i in slices[name]], dtype=int)

    public, inbox_test = sub("public_test"), sub("inbox_test")
    phish_2026, spam = sub("phish_2026_test"), sub("spam_folder")
    y_public = np.array([int(records[eval_ids[k]]["label"] == "phish") for k in public])
    groups = np.array([slices["sender_group"][eval_ids[k]] for k in inbox_test])
    categories = np.array([slices["category"][eval_ids[k]] for k in inbox_test])
    out = {}
    for model, f in flags.items():
        f = np.asarray(f)
        recall = float(f[public][y_public == 1].mean())
        inbox_fpr = share(f[inbox_test], n_bootstrap)
        per_sender = float(np.mean([f[inbox_test][groups == g].mean() for g in np.unique(groups)]))
        out[model] = {
            "public_recall": recall,
            "public_fpr": float(f[public][y_public == 0].mean()),
            "inbox_fpr": inbox_fpr,
            "inbox_fpr_per_sender": per_sender,
            "inbox_fpr_by_category": {
                c: share(f[inbox_test][categories == c], n_bootstrap) for c in np.unique(categories)
            },
            "phish_2026_recall": share(f[phish_2026], n_bootstrap),
            "spam_folder_flagged": share(f[spam], n_bootstrap),
            "precision_at_1_in_100": metrics.precision_at_prevalence(recall, inbox_fpr["share"]),
        }
    return out


def to_markdown(r: dict) -> str:
    c = r["counts"]
    lines = [
        "# Trained with part of my test inbox: before and after",
        "",
        "Generated by `make eval-with-inbox`. *Before:* the `random` split's models (public data only). *After:* the "
        "`with_inbox` split's, which adds "
        f"{c['inbox_train']} inbox emails to training and {c['inbox_val']} to validation (at most "
        f"{inbox.PER_SENDER_CAP} per sender) and as many 2026 phishing emails. Each model's threshold is chosen on "
        "its own validation data for 1% false alarms. Local models only; the inbox is never sent to an LLM.",
        "",
        f"Tested on the public `random` test ({c['public_test']:,} emails), {c['inbox_test']} inbox emails from "
        f"{c['inbox_test_senders']} senders neither model saw, {c['phish_2026_test']:,} 2026 phishing emails neither "
        f"model saw, and the {c['spam_folder']} Spam-folder emails. Brackets are 95% bootstrap intervals.",
        "",
        "| Model | | Public test: recall | Public test: false alarms | Inbox: false alarms | Inbox, averaged per "
        "sender | 2026 phishing: recall | Spam folder flagged | Precision @ 1 in 100 |",
        "|---|---|---:|---:|---|---:|---|---|---:|",
    ]
    for model, name in MODELS.items():
        for setup in ("before", "after"):
            v = r[setup][model]
            lines.append(
                f"| {name if setup == 'before' else ''} | {setup} | {v['public_recall']:.3f} | {v['public_fpr']:.2%} | "
                f"{fmt_share(v['inbox_fpr'])} | {v['inbox_fpr_per_sender']:.1%} | "
                f"{fmt_share(v['phish_2026_recall'])} | "
                f"{fmt_share(v['spam_folder_flagged'])} | {v['precision_at_1_in_100']:.3f} |"
            )
    lines += [
        "",
        "Precision @ 1 in 100: recall as on the public test, false alarms as on the inbox test senders.",
        "",
        "## Inbox false alarms by Gmail category (after)",
        "",
    ]
    cats = sorted(r["after"]["stacked"]["inbox_fpr_by_category"])
    lines += ["| Model | " + " | ".join(cats) + " |", "|---|" + "---|" * len(cats)]
    for model, name in MODELS.items():
        by = r["after"][model]["inbox_fpr_by_category"]
        lines.append(f"| {name} | " + " | ".join(fmt_share(by[k]) for k in cats) + " |")
    lines += [
        "",
        "## Date-word shortcut check (after)",
        "",
        "Years, month and weekday names removed from the test text. The rule, set before the first run: a change of "
        f"more than {SHORTCUT_POINTS:.0%} points in either column means the model leans on dates.",
        "",
        "| Model | Inbox false alarms: change | 2026 phishing recall: change | Shortcut? |",
        "|---|---:|---:|---|",
    ]
    for model, name in MODELS.items():
        d = r["date_check"][model]
        lines.append(
            f"| {name} | {d['inbox_fpr_change']:+.1%} | {d['phish_2026_recall_change']:+.1%} | "
            f"{'yes' if d['shortcut'] else 'no'} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bootstrap", type=int, default=metrics.N_BOOTSTRAP)
    args = parser.parse_args(argv)
    with_inbox, slices = inbox.load_split()
    splits = {"before": json.loads((SPLITS_DIR / "splits.json").read_text())["random"], "after": with_inbox}
    eval_ids = list(
        dict.fromkeys(slices["public_test"] + slices["inbox_test"] + slices["phish_2026_test"] + slices["spam_folder"])
    )
    ids = {i for s in splits.values() for part in ("train", "val") for i in s[part]} | set(eval_ids)
    records = inbox.read_split_records(ids)
    ranks = default_ranks()
    texts = {i: email_text(r) for i, r in records.items()}
    features = dict(zip(records, matrix(list(records.values()), ranks), strict=True))
    print(f"{len(records)} emails prepared", file=sys.stderr)

    result: dict = {
        "counts": {
            "inbox_train": sum(i in slices["category"] for i in with_inbox["train"]),
            "inbox_val": sum(i in slices["category"] for i in with_inbox["val"]),
            "public_test": len(slices["public_test"]),
            "inbox_test": len(slices["inbox_test"]),
            "inbox_test_senders": len(set(slices["sender_group"].values())),
            "phish_2026_test": len(slices["phish_2026_test"]),
            "spam_folder": len(slices["spam_folder"]),
        }
    }
    for setup in ("before", "after"):
        flags, dateless = evaluate_setup(splits[setup], eval_ids, records, ranks, texts, features, setup)
        result[setup] = measure(flags, eval_ids, records, slices, args.bootstrap)
        if setup == "after":
            plain = measure(dateless, eval_ids, records, slices, 20)
            result["date_check"] = {}
            for m in MODELS:
                fpr = plain[m]["inbox_fpr"]["share"] - result[setup][m]["inbox_fpr"]["share"]
                rec = plain[m]["phish_2026_recall"]["share"] - result[setup][m]["phish_2026_recall"]["share"]
                result["date_check"][m] = {
                    "inbox_fpr_change": fpr,
                    "phish_2026_recall_change": rec,
                    "shortcut": abs(fpr) > SHORTCUT_POINTS or abs(rec) > SHORTCUT_POINTS,
                }
        print(f"{setup}: done", file=sys.stderr)
    REPORTS_DIR.mkdir(exist_ok=True)
    (REPORTS_DIR / "with_inbox.json").write_text(json.dumps(result, indent=1) + "\n")
    (REPORTS_DIR / "with_inbox.md").write_text(to_markdown(result))
    print(to_markdown(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
