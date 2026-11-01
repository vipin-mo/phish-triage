"""Reproduce my course project's score, then measure how much of it survives a fairer evaluation.

    python -m phish_triage.evaluation.course

Steps, each changing one thing:

1. The course protocol on the course CSV: TF-IDF fitted on all rows (test rows included), 80/20 random split
   (seed 42), logistic regression, threshold 0.5.
2. The same, with TF-IDF fitted on the training rows only.
3. The same, after removing exact and near-duplicate rows (`data/dedup.py`).
4. Leave one source out: the course data rebuilt from its six source files; train on five, test on the sixth.
5. Transfer: the course model trained on the whole course CSV, tested on this project's own test emails.

Writes reports/course_reproduction.json and reports/course_reproduction.md (aggregate numbers only).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

from phish_triage.data import course, dedup
from phish_triage.data.records import MASKED_RECORDS, read_records
from phish_triage.data.splits import SPLITS_DIR
from phish_triage.evaluation import metrics
from phish_triage.models.baselines import course_model, email_text

REPORTS_DIR = Path("reports")
COURSE_SEED = 42  # the course notebook's random_state


def scores_at_half(y: np.ndarray, probs: np.ndarray) -> dict[str, float]:
    """Precision / recall / F1 at threshold 0.5 (how the course reported it), plus the threshold-free numbers."""
    flagged = probs >= 0.5
    tp = int((flagged & (y == 1)).sum())
    precision = tp / max(int(flagged.sum()), 1)
    recall = tp / max(int((y == 1).sum()), 1)
    fpr = float(flagged[y == 0].mean()) if (y == 0).any() else float("nan")
    return {
        "n": len(y),
        "positive_share": round(float(y.mean()), 3),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / max(precision + recall, 1e-12), 4),
        "false_alarm_rate": round(fpr, 4),
        "recall_at_1pct_fpr": round(metrics.recall_at_fpr(y, probs, 0.01), 4) if (y == 0).any() else None,
        "precision_at_1_in_100": round(metrics.precision_at_prevalence(recall, fpr), 4) if (y == 0).any() else None,
    }


def course_protocol(texts: list[str], y: np.ndarray, *, vectorizer_on_all: bool) -> dict[str, float]:
    train_i, test_i = train_test_split(np.arange(len(y)), test_size=0.2, stratify=y, random_state=COURSE_SEED)
    if vectorizer_on_all:  # what the notebook did: the vocabulary and IDF saw the test rows
        model = course_model()
        vectorizer: TfidfVectorizer = model.named_steps["tfidf"]
        x = vectorizer.fit_transform(texts)
        classifier = LogisticRegression(max_iter=1000, solver="liblinear").fit(x[train_i], y[train_i])
        probs = classifier.predict_proba(x[test_i])[:, 1]
    else:
        model = course_model().fit([texts[i] for i in train_i], y[train_i])
        probs = model.predict_proba([texts[i] for i in test_i])[:, 1]
    return scores_at_half(y[test_i], probs)


def unique_rows(texts: list[str], y: np.ndarray, sources: list[str] | None = None) -> np.ndarray:
    """Indices of the rows kept after exact and near-duplicate removal (label conflicts dropped)."""
    permutations = dedup.permutations()
    items = [
        dedup.make_item(
            {
                "id": f"{i:07d}",
                "source": sources[i] if sources else "course",
                "label": str(int(y[i])),
                "date": "",
                "subject": "",
                "text": text,
            },
            permutations,
        )
        for i, text in enumerate(texts)
    ]
    result = dedup.find_duplicates(items)
    return np.array(sorted(int(i) for i in result.keep))


def leave_one_source_out(texts: list[str], y: np.ndarray, sources: list[str]) -> dict[str, dict]:
    results = {}
    names = np.array(sources)
    for held_out in course.SOURCE_FILES.values():
        test = np.flatnonzero(names == held_out)
        train = np.flatnonzero(names != held_out)
        model = course_model().fit([texts[i] for i in train], y[train])
        results[held_out] = scores_at_half(y[test], model.predict_proba([texts[i] for i in test])[:, 1])
    return results


def transfer(texts: list[str], y: np.ndarray) -> dict[str, dict]:
    """Train on the whole course CSV (as the course did), test on this project's masked test emails."""
    model = course_model().fit(texts, y)
    splits = json.loads((SPLITS_DIR / "splits.json").read_text())
    results = {}
    for name in ("random", "by_time"):
        ids = splits[name]["test"]
        records = read_records(MASKED_RECORDS, set(ids))
        y_test = np.array([int(records[i]["label"] == "phish") for i in ids])
        probs = model.predict_proba([email_text(records[i]) for i in ids])[:, 1]
        results[name] = scores_at_half(y_test, probs)
    return results


def run() -> dict:
    texts, labels = course.combined()
    y = np.array(labels)
    results: dict = {"combined_rows": len(y)}
    print("1-2. course protocol", file=sys.stderr)
    results["course_protocol"] = course_protocol(texts, y, vectorizer_on_all=True)
    results["vectorizer_on_train_only"] = course_protocol(texts, y, vectorizer_on_all=False)

    print("3. after removing duplicates", file=sys.stderr)
    keep = unique_rows(texts, y)
    results["deduplicated_rows"] = len(keep)
    results["after_dedup"] = course_protocol([texts[i] for i in keep], y[keep], vectorizer_on_all=False)

    print("4. leave one source out", file=sys.stderr)
    s_texts, s_labels, s_sources = course.by_source()
    s_y = np.array(s_labels)
    keep = unique_rows(s_texts, s_y, s_sources)
    s_texts, s_y, s_sources = [s_texts[i] for i in keep], s_y[keep], [s_sources[i] for i in keep]
    results["rebuilt_rows"] = len(s_y)
    results["rebuilt_random_split"] = course_protocol(s_texts, s_y, vectorizer_on_all=False)
    results["leave_one_source_out"] = leave_one_source_out(s_texts, s_y, s_sources)
    results["source_composition"] = {
        source: {
            "rows": int((np.array(s_sources) == source).sum()),
            "label_1": int(s_y[np.array(s_sources) == source].sum()),
        }
        for source in course.SOURCE_FILES.values()
    }

    print("5. transfer to this project's test emails", file=sys.stderr)
    results["transfer"] = transfer(texts, y)
    return results


def to_markdown(r: dict) -> str:
    def row(label: str, s: dict) -> str:
        r1 = "" if s["recall_at_1pct_fpr"] is None else f"{s['recall_at_1pct_fpr']:.3f}"
        far = "" if np.isnan(s["false_alarm_rate"]) else f"{s['false_alarm_rate']:.2%}"
        return f"| {label} | {s['n']:,} | {s['precision']:.3f} | {s['recall']:.3f} | {s['f1']:.3f} | {far} | {r1} |"

    header = [
        "| Setting | Test emails | Precision | Recall | F1 | False alarms | Recall @ 1% FPR |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    lines = [
        "# Course project reproduction",
        "",
        "Generated by `make eval-course`. The model is the course's: word TF-IDF (10k features, 1-2 grams, English "
        "stop words) + logistic regression, threshold 0.5. Each row changes one thing.",
        "",
        "## On the course's own data",
        "",
        *header,
        row("1. Course protocol (TF-IDF fitted on all rows)", r["course_protocol"]),
        row("2. TF-IDF fitted on training rows only", r["vectorizer_on_train_only"]),
        row(
            f"3. After removing duplicates ({r['combined_rows']:,} -> {r['deduplicated_rows']:,} rows)",
            r["after_dedup"],
        ),
        row(
            f"4a. Rebuilt from the six source files, de-duplicated ({r['rebuilt_rows']:,} rows)",
            r["rebuilt_random_split"],
        ),
        "",
        "## 4b. Leave one source out (train on the other five)",
        "",
        '| Held-out source | Rows | Label 1 ("phishing") | Precision | Recall | False alarms | Recall @ 1% FPR |',
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for source, s in r["leave_one_source_out"].items():
        comp = r["source_composition"][source]
        far = "" if np.isnan(s["false_alarm_rate"]) else f"{s['false_alarm_rate']:.2%}"
        r1 = "" if s["recall_at_1pct_fpr"] is None else f"{s['recall_at_1pct_fpr']:.3f}"
        lines.append(
            f"| {source} | {comp['rows']:,} | {comp['label_1']:,} | {s['precision']:.3f} | {s['recall']:.3f} | "
            f"{far} | {r1} |"
        )
    lines += [
        "",
        "## 5. Trained on the course CSV, tested on this project's emails",
        "",
        *header,
        row("This project's `random` test (2015–2026)", r["transfer"]["random"]),
        row("This project's `by_time` test (2023–2026)", r["transfer"]["by_time"]),
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.parse_args(argv)
    results = run()
    REPORTS_DIR.mkdir(exist_ok=True)
    (REPORTS_DIR / "course_reproduction.json").write_text(json.dumps(results, indent=1) + "\n")
    (REPORTS_DIR / "course_reproduction.md").write_text(to_markdown(results))
    print(to_markdown(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
