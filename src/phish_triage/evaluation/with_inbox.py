"""Before and after: the models trained on public data only, with part of my private test inbox, and with
PrivacyMail newsletters too.

    python -m phish_triage.evaluation.with_inbox    # or `make eval-with-inbox` (after `make train-with-inbox`)

"Before" is the `random` split's models; "after" is the `with_inbox` split's (`random` plus part of the inbox and
2026 phishing, split by sender; see `data/inbox.py`); "newsletters" is the `with_newsletters` split's (that plus
English PrivacyMail newsletters, split by website; see `data/privacymail.py`), once built. Each model's threshold
is chosen on its own validation data for 1% false alarms. All are measured on:

- the public `random` test (does adding the inbox cost phishing recall?);
- the inbox's test senders, which neither model saw (false alarms per email, and averaged per sender);
- the PrivacyMail test websites, which no model saw (false alarms per email, and averaged per website);
- the 2026 phishing test emails (newest phishing; neither model saw these);
- the Spam folder (share flagged; it is not labelled).

**Date-word shortcut check.** The inbox is late 2026, so a model could learn "2026" or "November" as legitimate.
Removing years, month and weekday names from the test text must not change the inbox false-alarm rate or the
2026 phishing recall of the "after" models by more than 2 percentage points (rule set before the first run). The
first run found the TF-IDF models failing it; since then `email_text` removes date words from every model's input,
so the check is a guard that should read 0.

**Little-text rule.** `service.triage.too_little_text` sends emails with images or attachments but almost no visible
words to review; the cascade row with the rule counts review as flagged.

**Feature shortcut check.** Each structured feature on its own (ROC AUC, either direction): a feature that separates
the inbox's test senders from the 2026 phishing (AUC >= 0.9) but not the public test (< 0.7) only works because of
how the inbox differs from the training data, and is listed as a suspected shortcut (rule set before the run).
When there are suspects, the "after" models are refitted without them (set to missing), to show whether they change
what the cascade decides.

**Phishing that looks like a newsletter.** Phishing in the public and 2026 tests that is DKIM-signed by its own
domain and has at least `NEWSLETTER_LINKS` links, like the inbox's bulk mail. The feature check found the inbox's
legitimate mail looks like that, so this is where a model trained with it is most likely to miss phishing.

Local models only, never an LLM. Only counts and rates are written (reports/with_inbox.md, .json).
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

import numpy as np

from phish_triage.data import inbox, privacymail
from phish_triage.data.splits import SPLITS_DIR
from phish_triage.evaluation import metrics, predictions
from phish_triage.evaluation.cascade import run_cascade
from phish_triage.evaluation.test_inbox import MODELS, fmt_share, share
from phish_triage.features.domains import default_ranks
from phish_triage.features.extract import FEATURE_NAMES, matrix
from phish_triage.models.baselines import email_text, fit_all, without_dates
from phish_triage.service.triage import LITTLE_TEXT_WORDS, too_little_text

REPORTS_DIR = Path("reports")
ARTIFACTS_DIR = Path("artifacts")
SETUPS = {"before": "random", "after": inbox.SPLIT, "newsletters": privacymail.NEWSLETTER_SPLIT}
DISTILBERT = "distilbert_head"  # served as ONNX fp32: int8 scores depend on the batch
SHORTCUT_POINTS = 0.02
SUSPECT_AUC, PUBLIC_MAX_AUC = 0.9, 0.7
NEWSLETTER_LINKS = 12  # the median number of links in the inbox's test emails
MODEL_NAMES = MODELS | {"cascade_review": "Cascade + little-text rule (review counts as flagged)"}


def _distilbert(split: str, val_ids: list[str], eval_ids: list[str], records: dict, texts: dict) -> tuple:
    """Validation and evaluation scores: saved predictions where they exist, the exported ONNX fp32 model otherwise."""
    from phish_triage.models.transformer import OnnxClassifier

    saved = predictions.load(split, DISTILBERT)
    if saved.val_ids != val_ids:  # the split changed since training: these scores are of another model's data
        raise SystemExit(f"saved DistilBERT predictions don't match the {split} validation split; re-run training")
    known = dict(zip(saved.val_ids, saved.val_scores, strict=True)) | dict(
        zip(saved.test_ids, saved.test_scores, strict=True)
    )
    missing = [i for i in eval_ids if i not in known]
    folder = "distilbert" if split == "random" else f"distilbert_{split}"
    classifier = OnnxClassifier(ARTIFACTS_DIR / folder / "model.onnx", threads=4)
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

    review = np.array([too_little_text(records[i]) for i in eval_ids], dtype=int)

    def flags_for(s: dict) -> dict[str, np.ndarray]:
        out = {m: (s[m] > thresholds[m]).astype(int) for m in thresholds}
        out["cascade"] = run_cascade(cascade_val, [s["stacked"], s["distilbert"]], thresholds["distilbert"]).decisions
        out["cascade_review"] = np.maximum(out["cascade"], review)
        return out

    return flags_for(scores), flags_for(dateless)


def measure(flags: dict[str, np.ndarray], eval_ids: list[str], records: dict, slices: dict, n_bootstrap: int) -> dict:
    position = {i: k for k, i in enumerate(eval_ids)}

    def sub(name: str) -> np.ndarray:
        return np.array([position[i] for i in slices[name]], dtype=int)

    public, inbox_test = sub("public_test"), sub("inbox_test")
    phish_2026, spam = sub("phish_2026_test"), sub("spam_folder")
    newsletter_like = sub("newsletter_like_phish")
    y_public = np.array([int(records[eval_ids[k]]["label"] == "phish") for k in public])
    groups = np.array([slices["sender_group"][eval_ids[k]] for k in inbox_test])
    newsletters = sub("privacymail_test") if "privacymail_test" in slices else None
    sites = np.array([slices["website"][eval_ids[k]] for k in newsletters]) if newsletters is not None else None
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
            "newsletter_like_recall": share(f[newsletter_like], n_bootstrap),
            "spam_folder_flagged": share(f[spam], n_bootstrap),
            "precision_at_1_in_100": metrics.precision_at_prevalence(recall, inbox_fpr["share"]),
        }
        if newsletters is not None:
            out[model]["privacymail_fpr"] = share(f[newsletters], n_bootstrap)
            out[model]["privacymail_fpr_per_website"] = float(
                np.mean([f[newsletters][sites == s].mean() for s in np.unique(sites)])
            )
    return out


def to_markdown(r: dict) -> str:
    c = r["counts"]
    present = [s for s in SETUPS if s in r]
    lines = [
        "# Trained with part of my test inbox: before and after",
        "",
        "Generated by `make eval-with-inbox`. *Before:* the `random` split's models (public data only). *After:* the "
        "`with_inbox` split's, which adds "
        f"{c['inbox_train']} inbox emails to training and {c['inbox_val']} to validation (at most "
        f"{inbox.PER_SENDER_CAP} per sender) and as many 2026 phishing emails. Each model's threshold is chosen on "
        "its own validation data for 1% false alarms. Local models only; the inbox is never sent to an LLM.",
        *(
            [
                "",
                f"*Newsletters:* the `with_newsletters` split's, which also adds {c['newsletters_train']:,} "
                f"PrivacyMail newsletters to training and {c['newsletters_val']:,} to validation (at most "
                f"{privacymail.PER_WEBSITE_TRAIN} per website, from websites kept out of the test), after the "
                "deployed model flagged 76.5% of them (reports/privacymail.md).",
            ]
            if "newsletters" in present
            else []
        ),
        "",
        f"Tested on the public `random` test ({c['public_test']:,} emails), {c['inbox_test']} inbox emails from "
        f"{c['inbox_test_senders']} senders neither model saw, {c['phish_2026_test']:,} 2026 phishing emails neither "
        f"model saw, and the {c['spam_folder']} Spam-folder emails. Brackets are 95% bootstrap intervals.",
        "",
        "| Model | | Public test: recall | Public test: false alarms | Inbox: false alarms | Inbox, averaged per "
        "sender | 2026 phishing: recall | Spam folder flagged | Precision @ 1 in 100 |",
        "|---|---|---:|---:|---|---:|---|---|---:|",
    ]
    for model, name in MODEL_NAMES.items():
        for setup in [s for s in SETUPS if s in r]:
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
    for model, name in MODEL_NAMES.items():
        by = r["after"][model]["inbox_fpr_by_category"]
        lines.append(f"| {name} | " + " | ".join(fmt_share(by[k]) for k in cats) + " |")
    lines += [
        "",
        "## Date-word shortcut check (after)",
        "",
        "Years, month and weekday names removed from the test text. The rule, set before the first run: a change of "
        f"more than {SHORTCUT_POINTS:.0%} points in either column means the model leans on dates. Every model's input "
        "has had date words removed since the first run failed the TF-IDF models, so this now guards against that "
        "being undone and should read 0.",
        "",
        "| Model | Inbox false alarms: change | 2026 phishing recall: change | Shortcut? |",
        "|---|---:|---:|---|",
    ]
    for model, name in MODEL_NAMES.items():
        d = r["date_check"][model]
        lines.append(
            f"| {name} | {d['inbox_fpr_change']:+.1%} | {d['phish_2026_recall_change']:+.1%} | "
            f"{'yes' if d['shortcut'] else 'no'} |"
        )
    lines += [
        "",
        "## Little-text rule",
        "",
        f"Emails with images or attachments but fewer than {LITTLE_TEXT_WORDS} visible words go to review.",
        "",
        "| Test slice | Sent to review |",
        "|---|---|",
        *[f"| {name} | {fmt_share(r['little_text'][key])} |" for key, name in SLICE_NAMES.items()],
        "",
        "## Feature shortcut check",
        "",
        f"Each structured feature on its own (ROC AUC, either direction). Suspected shortcut: AUC >= {SUSPECT_AUC} "
        f"between the inbox's test senders and the 2026 phishing, but < {PUBLIC_MAX_AUC} on the public test (rule set "
        "before the run).",
        "",
    ]
    suspects = r["feature_check"]["suspects"]
    if suspects:
        lines += ["| Feature | Inbox vs 2026 phishing | Public test |", "|---|---:|---:|"]
        lines += [f"| `{f}` | {v['inbox']:.3f} | {v['public']:.3f} |" for f, v in suspects.items()]
        without = r["feature_check"].get("without_suspects")
        if without:
            lines += [
                "",
                "The cascade refitted without them (set to missing):",
                "",
                "| | Inbox: false alarms | 2026 phishing: recall | Phishing that looks like a newsletter: recall |",
                "|---|---|---|---|",
            ]
            for name, v in (("as trained", r["after"]["cascade"]), ("without the suspects", without)):
                lines.append(
                    f"| {name} | {fmt_share(v['inbox_fpr'])} | {fmt_share(v['phish_2026_recall'])} | "
                    f"{fmt_share(v['newsletter_like_recall'])} |"
                )
    else:
        lines.append(f"None of the {len(r['feature_check']['auc'])} features is a suspected shortcut.")
    strongest = sorted(r["feature_check"]["auc"].items(), key=lambda kv: -kv[1]["inbox"])[:5]
    lines += [
        "",
        "Strongest on the inbox: "
        + ", ".join(f"`{f}` {v['inbox']:.3f} (public {v['public']:.3f})" for f, v in strongest)
        + ".",
        "",
        "## Phishing that looks like a newsletter",
        "",
        f"Phishing in the public and 2026 tests that is DKIM-signed by its own domain and has at least "
        f"{NEWSLETTER_LINKS} links, like the inbox's bulk mail: {c['newsletter_like_phish']} emails. With so few, the "
        "intervals are wide.",
        "",
        "| Model | " + " | ".join(s.capitalize() for s in present) + " |",
        "|---|" + "---|" * len(present),
        *[
            f"| {name} | " + " | ".join(fmt_share(r[s][m]["newsletter_like_recall"]) for s in present) + " |"
            for m, name in MODEL_NAMES.items()
        ],
    ]
    if "privacymail_fpr" in r["before"]["cascade"]:
        lines += [
            "",
            "## PrivacyMail: newsletters from websites no model saw",
            "",
            f"{c['privacymail_test']:,} English newsletters from {c['privacymail_test_websites']} websites "
            "(PrivacyMail, 2019–2022) held out of the `newsletters` setup's training; the other two setups never saw "
            "PrivacyMail at all. Every email counts as legitimate. Only these aggregates leave the private folder.",
            "",
            "| Model | "
            + " | ".join(f"{s.capitalize()}: false alarms" for s in present)
            + " | "
            + " | ".join(f"{s.capitalize()}: per website" for s in present)
            + " |",
            "|---|" + "---|" * len(present) + "---:|" * len(present),
            *[
                f"| {name} | "
                + " | ".join(fmt_share(r[s][m]["privacymail_fpr"]) for s in present)
                + " | "
                + " | ".join(f"{r[s][m]['privacymail_fpr_per_website']:.1%}" for s in present)
                + " |"
                for m, name in MODEL_NAMES.items()
            ],
        ]
    return "\n".join(lines) + "\n"


SLICE_NAMES = {
    "public_legit": "Public test, legitimate",
    "public_phish": "Public test, phishing",
    "inbox_test": "Inbox test senders",
    "phish_2026_test": "2026 phishing",
}


def feature_check(features: dict, records: dict, slices: dict) -> dict:
    from sklearn.metrics import roc_auc_score

    def auc(legit: list[str], phish: list[str], k: int) -> float:
        x = np.nan_to_num(np.array([features[i][k] for i in legit + phish], dtype=float), nan=-1.0)
        y = np.r_[np.zeros(len(legit)), np.ones(len(phish))]
        if len(np.unique(x)) < 2:
            return 0.5
        a = float(roc_auc_score(y, x))
        return max(a, 1 - a)

    public = slices["public_test"]
    public_legit = [i for i in public if records[i]["label"] != "phish"]
    public_phish = [i for i in public if records[i]["label"] == "phish"]
    out = {
        name: {
            "inbox": auc(slices["inbox_test"], slices["phish_2026_test"], k),
            "public": auc(public_legit, public_phish, k),
        }
        for k, name in enumerate(FEATURE_NAMES)
    }
    suspects = {f: v for f, v in out.items() if v["inbox"] >= SUSPECT_AUC and v["public"] < PUBLIC_MAX_AUC}
    return {"auc": out, "suspects": suspects}


def newsletter_like_phish(features: dict, records: dict, slices: dict) -> list[str]:
    aligned, links = FEATURE_NAMES.index("dkim_aligned"), FEATURE_NAMES.index("n_urls")
    phish = [i for i in slices["public_test"] if records[i]["label"] == "phish"] + slices["phish_2026_test"]
    # `n_urls` is log1p of the count
    return [i for i in phish if features[i][aligned] == 1 and features[i][links] >= math.log1p(NEWSLETTER_LINKS)]


def little_text(records: dict, slices: dict, n_bootstrap: int) -> dict:
    public = slices["public_test"]
    members = {
        "public_legit": [i for i in public if records[i]["label"] != "phish"],
        "public_phish": [i for i in public if records[i]["label"] == "phish"],
        "inbox_test": slices["inbox_test"],
        "phish_2026_test": slices["phish_2026_test"],
    }
    return {
        k: share(np.array([too_little_text(records[i]) for i in ids], dtype=int), n_bootstrap)
        for k, ids in members.items()
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bootstrap", type=int, default=metrics.N_BOOTSTRAP)
    args = parser.parse_args(argv)
    with_inbox, slices = inbox.load_split()
    splits = {"before": json.loads((SPLITS_DIR / "splits.json").read_text())["random"], "after": with_inbox}
    if privacymail.SPLIT_FILE.exists():  # the newsletters setup, once `make data-privacymail` has built it
        splits["newsletters"], newsletter_slices = privacymail.load_split()
        slices = slices | newsletter_slices
    eval_ids = list(
        dict.fromkeys(
            slices["public_test"]
            + slices["inbox_test"]
            + slices["phish_2026_test"]
            + slices["spam_folder"]
            + slices.get("privacymail_test", [])
        )
    )
    ids = {i for s in splits.values() for part in ("train", "val") for i in s[part]} | set(eval_ids)
    records = inbox.read_split_records(ids)
    ranks = default_ranks()
    texts = {i: email_text(r) for i, r in records.items()}
    features = dict(zip(records, matrix(list(records.values()), ranks), strict=True))
    print(f"{len(records)} emails prepared", file=sys.stderr)
    slices = slices | {"newsletter_like_phish": newsletter_like_phish(features, records, slices)}

    result: dict = {
        "counts": {
            "inbox_train": sum(i in slices["category"] for i in with_inbox["train"]),
            "inbox_val": sum(i in slices["category"] for i in with_inbox["val"]),
            "public_test": len(slices["public_test"]),
            "inbox_test": len(slices["inbox_test"]),
            "inbox_test_senders": len(set(slices["sender_group"].values())),
            "phish_2026_test": len(slices["phish_2026_test"]),
            "spam_folder": len(slices["spam_folder"]),
            "newsletter_like_phish": len(slices["newsletter_like_phish"]),
            "privacymail_test": len(slices.get("privacymail_test", [])),
            **{
                f"newsletters_{part}": len(splits["newsletters"][part]) - len(with_inbox[part])
                if "newsletters" in splits
                else 0
                for part in ("train", "val")
            },
            "privacymail_test_websites": len(set(slices.get("website", {}).values())),
        }
    }
    for setup in splits:
        flags, dateless = evaluate_setup(splits[setup], eval_ids, records, ranks, texts, features, setup)
        result[setup] = measure(flags, eval_ids, records, slices, args.bootstrap)
        if setup == "after":
            plain = measure(dateless, eval_ids, records, slices, 20)
            result["date_check"] = {}
            for m in MODEL_NAMES:
                fpr = plain[m]["inbox_fpr"]["share"] - result[setup][m]["inbox_fpr"]["share"]
                rec = plain[m]["phish_2026_recall"]["share"] - result[setup][m]["phish_2026_recall"]["share"]
                result["date_check"][m] = {
                    "inbox_fpr_change": fpr,
                    "phish_2026_recall_change": rec,
                    "shortcut": abs(fpr) > SHORTCUT_POINTS or abs(rec) > SHORTCUT_POINTS,
                }
        print(f"{setup}: done", file=sys.stderr)
    result["little_text"] = little_text(records, slices, args.bootstrap)
    result["feature_check"] = feature_check(features, records, slices)
    if result["feature_check"]["suspects"]:
        hidden = [FEATURE_NAMES.index(f) for f in result["feature_check"]["suspects"]]
        masked = {i: np.where(np.isin(np.arange(len(v)), hidden), np.nan, v) for i, v in features.items()}
        flags, _ = evaluate_setup(splits["after"], eval_ids, records, ranks, texts, masked, "after")
        without = measure({"cascade": flags["cascade"]}, eval_ids, records, slices, args.bootstrap)["cascade"]
        result["feature_check"]["without_suspects"] = without
    REPORTS_DIR.mkdir(exist_ok=True)
    (REPORTS_DIR / "with_inbox.json").write_text(json.dumps(result, indent=1) + "\n")
    (REPORTS_DIR / "with_inbox.md").write_text(to_markdown(result))
    print(to_markdown(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
