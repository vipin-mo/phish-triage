"""Leakage audit: can a model tell phishing from legitimate mail using things that have nothing to do with phishing?

    python -m phish_triage.data.audit

For each "cheat" feature group (header names, header order, recipient domain, the Authentication-Results server,
Message-ID domain, date) it trains a logistic regression on the `random` split and reports ROC AUC on the test
part, once on the raw records and once on the masked ones. An AUC near 0.5 means the group carries no label
signal; near 1.0 means it alone separates the classes, so a model could score well by recognising the dataset.

The normalized `auth` field (kept out of the masked headers) is tested separately, to show why it stays out.
It also reports a text baseline (TF-IDF on subject + body) with its strongest words, a "which phishing source?"
classifier, and the date baseline on the deliberately confounded `old_era` split.

Writes reports/leakage_audit.json and reports/leakage_audit.md. Only aggregate numbers and feature names are
written, never email content.
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
from collections.abc import Callable, Iterable
from email.utils import getaddresses
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score

from phish_triage.data.build import INTERIM_DIR
from phish_triage.data.splits import SPLITS_DIR

REPORTS_DIR = Path("reports")
TEXT_CHARS = 20_000
TOP_FEATURES = 10
_WORD_RE = re.compile(r"[a-z0-9][a-z0-9.-]*[a-z0-9]|[a-z0-9]")
TEXT_WORDS = r"(?u)\b[a-zA-Z][a-zA-Z]+\b"  # words of 2+ letters; numbers carry dates and ids


def header_names(r: dict) -> list[str]:
    return sorted({name.lower() for name, _ in r["headers"]})


def header_order(r: dict) -> list[str]:
    names = [name.lower() for name, _ in r["headers"]]
    return [f"{a} > {b}" for a, b in zip(names, names[1:], strict=False)]


def recipient_domain(r: dict) -> list[str]:
    found = set()
    for name, value in r["headers"]:
        if name.lower() in ("to", "cc", "delivered-to", "x-original-to"):
            found |= {f"{name.lower()}:{a.rpartition('@')[2].lower()}" for _, a in getaddresses([value]) if "@" in a}
    return sorted(found) or ["none"]


def auth_server(r: dict) -> list[str]:
    values = [v for name, v in r["headers"] if name.lower() == "authentication-results"]
    return sorted({w for v in values for w in _WORD_RE.findall(v.lower())}) or ["absent"]


def message_id_domain(r: dict) -> list[str]:
    value = next((v for name, v in r["headers"] if name.lower() == "message-id"), "")
    return [value.rpartition("@")[2].strip(" >").lower() or "none"]


def date(r: dict) -> list[str]:
    return [f"year:{r['date'][:4]}", f"month:{r['date'][5:7]}"] if r["date"] else ["none"]


GROUPS: dict[str, Callable[[dict], list[str]]] = {
    "header names": header_names,
    "header order": header_order,
    "recipient domain": recipient_domain,
    "Authentication-Results": auth_server,
    "Message-ID domain": message_id_domain,
    "date": date,
}


def text(r: dict) -> str:
    return f"{r['subject']}\n{r['text'][:TEXT_CHARS]}"


def read(path: Path, ids: set[str]) -> dict[str, dict]:
    """Records whose id is in `ids`. The id is the first field, so other lines are skipped without parsing."""
    found = {}
    with gzip.open(path, "rt", encoding="utf-8") as lines:
        for line in lines:
            if line[8:24] in ids and line[8:24] not in found:
                record = json.loads(line)
                found[record["id"]] = record
    return found


def fit(
    train: list, y_train: np.ndarray, test: list, y_test: np.ndarray, *, tokens: bool
) -> tuple[float, list[str], list[str]]:
    """ROC AUC on test, and the strongest features for each class (positive class first)."""
    if tokens:
        vectorizer = CountVectorizer(analyzer=_identity, binary=True, min_df=2)
    else:
        vectorizer = TfidfVectorizer(token_pattern=TEXT_WORDS, min_df=5, sublinear_tf=True)
    x_train = vectorizer.fit_transform(train)
    model = LogisticRegression(max_iter=2000).fit(x_train, y_train)
    auc = roc_auc_score(y_test, model.predict_proba(vectorizer.transform(test))[:, 1])
    names, order = vectorizer.get_feature_names_out(), np.argsort(model.coef_[0])
    return (
        float(auc),
        [str(names[i]) for i in order[::-1][:TOP_FEATURES]],
        [str(names[i]) for i in order[:TOP_FEATURES]],
    )


def _identity(tokens: list[str]) -> list[str]:
    return tokens


def audit(interim: Path = INTERIM_DIR, splits_dir: Path = SPLITS_DIR) -> dict:
    splits = json.loads((splits_dir / "splits.json").read_text())
    main, old = splits["random"], splits["old_era"]
    wanted = {i for part in (main["train"], main["test"], old["train"], old["test"]) for i in part}
    raw = read(interim / "records.jsonl.gz", wanted)
    masked = read(interim / "masked.jsonl.gz", wanted)
    print(f"read {len(raw)} raw and {len(masked)} masked records", file=sys.stderr)

    def data(view: dict, ids: list[str], positive: Callable[[dict], bool]) -> tuple[list[dict], np.ndarray]:
        records = [view[i] for i in ids]
        return records, np.array([positive(r) for r in records], dtype=int)

    is_phish = lambda r: r["label"] == "phish"  # noqa: E731
    results: dict = {"cheat_baselines": [], "kept_aside": [], "text": [], "phishing_source": [], "old_era": []}
    for group, extract in GROUPS.items():
        row = {"group": group}
        for view_name, view in (("raw", raw), ("masked", masked)):
            train, y_train = data(view, main["train"], is_phish)
            test, y_test = data(view, main["test"], is_phish)
            auc, top_phish, top_legit = fit(
                [extract(r) for r in train], y_train, [extract(r) for r in test], y_test, tokens=True
            )
            row[view_name] = {"auc": round(auc, 3), "top_phish": top_phish, "top_legit": top_legit}
        results["cheat_baselines"].append(row)
        print(f"{group}: raw {row['raw']['auc']}, masked {row['masked']['auc']}", file=sys.stderr)

    train, y_train = data(masked, main["train"], is_phish)
    test, y_test = data(masked, main["test"], is_phish)
    auth = lambda r: (r["auth"] or "absent").split()  # noqa: E731
    auc, top_phish, top_legit = fit([auth(r) for r in train], y_train, [auth(r) for r in test], y_test, tokens=True)
    results["kept_aside"].append(
        {"field": "auth", "auc": round(auc, 3), "top_phish": top_phish, "top_legit": top_legit}
    )

    for view_name, view in (("raw", raw), ("masked", masked)):
        train, y_train = data(view, main["train"], is_phish)
        test, y_test = data(view, main["test"], is_phish)
        auc, top_phish, top_legit = fit(
            [text(r) for r in train], y_train, [text(r) for r in test], y_test, tokens=False
        )
        results["text"].append(
            {"view": view_name, "auc": round(auc, 3), "top_phish": top_phish, "top_legit": top_legit}
        )

    # Which phishing source? High is expected (they are different collections); the features show what differs.
    phish_train = [i for i in main["train"] if masked[i]["label"] == "phish"]
    phish_test = [i for i in main["test"] if masked[i]["label"] == "phish"]
    is_pot = lambda r: r["source"] == "phishing_pot"  # noqa: E731
    train, y_train = data(masked, phish_train, is_pot)
    test, y_test = data(masked, phish_test, is_pot)
    for name, extract, tokens in (("header names", header_names, True), ("text", text, False)):
        auc, top_pot, top_nazario = fit(
            [extract(r) for r in train], y_train, [extract(r) for r in test], y_test, tokens=tokens
        )
        results["phishing_source"].append(
            {"features": name, "auc": round(auc, 3), "top_phishing_pot": top_pot, "top_nazario": top_nazario}
        )

    for name, extract, tokens in (("date", date, True), ("text", text, False)):
        train, y_train = data(masked, old["train"], is_phish)
        test, y_test = data(masked, old["test"], is_phish)
        auc, _, _ = fit([extract(r) for r in train], y_train, [extract(r) for r in test], y_test, tokens=tokens)
        results["old_era"].append({"features": name, "auc": round(auc, 3)})

    results["sizes"] = {"random_train": len(main["train"]), "random_test": len(main["test"])}
    return results


def to_markdown(results: dict) -> str:
    lines = [
        "# Leakage audit",
        "",
        "Generated by `python -m phish_triage.data.audit`. ROC AUC on the test part of the `random` split "
        f"({results['sizes']['random_train']:,} train / {results['sizes']['random_test']:,} test emails). "
        "0.5 means no signal; 1.0 means the features alone separate phishing from legitimate mail.",
        "",
        "## Features that should not predict phishing",
        "",
        "| Feature group | Raw AUC | Masked AUC | Strongest masked features (phishing / legitimate) |",
        "|---|---:|---:|---|",
    ]
    for row in results["cheat_baselines"]:
        top = f"{_codes(row['masked']['top_phish'][:4])} / {_codes(row['masked']['top_legit'][:4])}"
        lines.append(f"| {row['group']} | {row['raw']['auc']:.3f} | {row['masked']['auc']:.3f} | {top} |")
    lines += [
        "",
        "## Kept out of the masked headers",
        "",
        "| Field | AUC | Strongest values (phishing / legitimate) |",
        "|---|---:|---|",
    ]
    for row in results["kept_aside"]:
        top = f"{_codes(row['top_phish'][:4])} / {_codes(row['top_legit'][:4])}"
        lines.append(f"| `{row['field']}` (normalized Authentication-Results) | {row['auc']:.3f} | {top} |")
    lines += [
        "",
        "## Text (subject + body, TF-IDF)",
        "",
        "| View | AUC | Strongest phishing words | Strongest legitimate words |",
    ]
    lines += ["|---|---:|---|---|"]
    for row in results["text"]:
        lines.append(f"| {row['view']} | {row['auc']:.3f} | {_codes(row['top_phish'])} | {_codes(row['top_legit'])} |")
    lines += [
        "",
        "## Which phishing source? (masked, phishing emails only)",
        "",
        "| Features | AUC | phishing_pot | Nazario |",
    ]
    lines += ["|---|---:|---|---|"]
    for row in results["phishing_source"]:
        lines.append(
            f"| {row['features']} | {row['auc']:.3f} | {_codes(row['top_phishing_pot'][:5])} | "
            f"{_codes(row['top_nazario'][:5])} |"
        )
    lines += [
        "",
        "## The confounded old-era split (Nazario 2004-2014 vs SpamAssassin 2002, masked)",
        "",
        "| Features | AUC |",
    ]
    lines += ["|---|---:|"] + [f"| {row['features']} | {row['auc']:.3f} |" for row in results["old_era"]]
    return "\n".join(lines) + "\n"


def _codes(values: Iterable[str]) -> str:
    return ", ".join(f"`{v}`" for v in values)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.parse_args(argv)
    results = audit()
    REPORTS_DIR.mkdir(exist_ok=True)
    (REPORTS_DIR / "leakage_audit.json").write_text(json.dumps(results, indent=1) + "\n")
    (REPORTS_DIR / "leakage_audit.md").write_text(to_markdown(results))
    print(to_markdown(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
