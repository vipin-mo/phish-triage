"""How much does detection lean on the sender and authentication features? (batch 3: reports/sender_ablation.md)

    python -m phish_triage.evaluation.sender_ablation    # or `make sender-ablation`; $0, nothing goes to an LLM

Stage 1 of the deployed cascade is refitted on the deployed split (`with_normalized`, reader 2) three times, its
cutoffs chosen again on validation each time:

- **all features:** as deployed, a check that the refit reproduces the deployed cascade's counts (reports/defence.md,
  setup d);
- **without DKIM:** `dkim_signed` and `dkim_aligned` left out, the only authentication features the models see;
- **without the header features:** all 11 left out (sender domain, rank, look-alike, display name, Reply-To, To,
  DKIM), so stage 1 has only the link, HTML, attachment and text signals.

DistilBERT reads only the subject and body, so it and its threshold stay as deployed. The tests are the deployed
split's clean tests (`defence.test_sets`). The private tests are scored on this laptop and only their counts are
written.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

REPORTS_DIR = Path("reports")
AUTH = ("dkim_signed", "dkim_aligned")
SETUP_NAMES = {
    "all": "All features",
    "no_dkim": "Without DKIM",
    "no_header": "Without the header features",
}


def left_out(setup: str) -> tuple[str, ...]:
    from phish_triage.features.extract import HEADER_FEATURES

    return {"all": (), "no_dkim": AUTH, "no_header": HEADER_FEATURES}[setup]


def blank(features: np.ndarray, names: tuple[str, ...]) -> np.ndarray:
    """The feature matrix with `names` missing on every row, which the trees then drop (`DropEmptyColumns`)."""
    from phish_triage.features.extract import FEATURE_NAMES

    out = features.copy()
    out[:, [FEATURE_NAMES.index(n) for n in names]] = np.nan
    return out


def measure() -> dict:
    from phish_triage.data import inbox
    from phish_triage.evaluation.cascade import choose_cutoffs, decide
    from phish_triage.evaluation.defence import test_sets
    from phish_triage.features.domains import default_ranks
    from phish_triage.features.extract import matrix
    from phish_triage.models.baselines import email_text, fit_all
    from phish_triage.service.bundle import DEPLOYED_SPLIT, latest, load_split, reader_of
    from phish_triage.service.scanner import Scanner

    reader = reader_of(DEPLOYED_SPLIT)
    split, _ = load_split(DEPLOYED_SPLIT)
    sets, test_records = test_sets()
    records = inbox.read_split_records(set(split["train"]) | set(split["val"])) | test_records
    tests = sorted({i for ids in sets.values() for i in ids})
    ranks = default_ranks()

    def part(ids: list[str]):
        rows = [records[i] for i in ids]
        texts = [email_text(r, reader) for r in rows]
        return texts, matrix(rows, ranks, reader), np.array([int(r["label"] == "phish") for r in rows])

    print("reading the emails", file=sys.stderr)
    train, val, test = part(split["train"]), part(split["val"]), part(tests)
    scanner = Scanner(latest(split=DEPLOYED_SPLIT), threads=4)
    print(f"DistilBERT on {len(tests):,} test emails ({scanner.version})", file=sys.stderr)
    distilbert = np.asarray(scanner._distilbert.score(test[0]))
    threshold = scanner.config["distilbert_threshold"]
    where = {i: k for k, i in enumerate(tests)}

    out: dict = {"bundle": scanner.version, "reader": reader, "setups": {}}
    for setup in SETUP_NAMES:
        names = left_out(setup)
        print(f"{setup}: fitting stage 1 without {len(names)} features", file=sys.stderr)
        fitted = fit_all(train[0], blank(train[1], names), train[2], val[0], blank(val[1], names), val[2])
        cutoffs = choose_cutoffs(val[2], fitted.scores(val[0], blank(val[1], names))["stacked"])
        stage1 = decide(fitted.scores(test[0], blank(test[1], names))["stacked"], cutoffs)
        flagged = np.where(stage1 >= 0, stage1 == 1, distilbert > threshold)
        result = {"left_out": list(names), "cutoffs": {"low": cutoffs.low, "high": cutoffs.high}, "tests": {}}
        for name, ids in sets.items():
            rows = [where[i] for i in ids]
            result["tests"][name] = {
                "emails": len(ids),
                "flagged": int(flagged[rows].sum()),
                "stage1_decided": int((stage1[rows] >= 0).sum()),
            }
        out["setups"][setup] = result
        print(json.dumps(result["tests"]), file=sys.stderr)
    return out


# --- The report ---

ROWS = {
    "public_phish": "Public test, phishing caught",
    "phish_2026": "2026 phishing caught",
    "newsletter_like_phish": "Newsletter-like phishing caught",
    "public_legit": "Public test, legitimate flagged",
    "inbox_test": "My inbox's test senders flagged",
    "privacymail_test": "PrivacyMail held-out websites flagged",
}
STAGE1_ROWS = {
    "public_phish": "Public test, phishing",
    "public_legit": "Public test, legitimate",
    "phish_2026": "2026 phishing",
    "newsletter_like_phish": "Newsletter-like phishing",
    "inbox_test": "My inbox's test senders",
    "privacymail_test": "PrivacyMail held-out websites",
}
COUNTS = ("newsletter_like_phish", "inbox_test")


def to_markdown(r: dict) -> str:
    setups = list(r["setups"])
    header = "| | " + " | ".join(SETUP_NAMES[s] for s in setups) + " |"
    rule = "|---|" + "---:|" * len(setups)

    def cell(v: dict, counts: bool) -> str:
        share = f"{v['flagged'] / v['emails']:.1%} ({v['flagged']:,})"
        return f"{v['flagged']} of {v['emails']:,}" if counts else share

    def row(key: str, label: str, value) -> str:
        return f"| {label} | " + " | ".join(value(r["setups"][s]["tests"][key]) for s in setups) + " |"

    lines = [
        "# How much detection leans on the sender features",
        "",
        "Generated by `make sender-ablation`. Stage 1 of the deployed cascade "
        f"(`{r['bundle']}`, reader {r['reader']}) refitted on the deployed split without some features, its cutoffs "
        "chosen again on validation; DistilBERT, which reads only the subject and body, is unchanged. *Without DKIM* "
        "leaves out `dkim_signed` and `dkim_aligned`, the only authentication features the models see (SPF and DMARC "
        "results are shown to me but never reach a model). *Without the header features* leaves out all 11: the "
        "sender's domain, its rank, look-alike and free-mail checks, the display name, Reply-To, To and DKIM. The "
        "private tests are scored on my laptop; only counts are shown.",
        "",
        "## Flagged",
        "",
        header,
        rule,
        *[row(k, label, lambda v, k=k: cell(v, k in COUNTS)) for k, label in ROWS.items()],
        "",
        *_refit_check(r),
        "## Decided by stage 1",
        "",
        "The rest go to DistilBERT.",
        "",
        header,
        rule,
        *[row(k, label, _stage1) for k, label in STAGE1_ROWS.items()],
        "",
    ]
    return "\n".join(lines)


def _refit_check(r: dict) -> list[str]:
    """Whether the refit with every feature gives the deployed cascade's counts (reports/defence.json, setup d)."""
    path = REPORTS_DIR / "defence.json"
    if not path.exists() or "d_normalized" not in json.loads(path.read_text())["setups"]:
        return []
    deployed = json.loads(path.read_text())["setups"]["d_normalized"]["clean"]
    same = all(deployed[k]["flagged"] == v["flagged"] for k, v in r["setups"]["all"]["tests"].items())
    word = "matches" if same else "does NOT match"
    return [f"The refit with all features {word} the deployed cascade's counts (reports/defence.md, setup d).", ""]


def _stage1(v: dict) -> str:
    return f"{v['stage1_decided'] / v['emails']:.0%}"


def main(argv: list[str] | None = None) -> int:
    REPORTS_DIR.mkdir(exist_ok=True)
    path = REPORTS_DIR / "sender_ablation.json"
    if not (argv and argv[0] == "report"):
        path.write_text(json.dumps(measure(), indent=1) + "\n")
    text = to_markdown(json.loads(path.read_text()))
    (REPORTS_DIR / "sender_ablation.md").write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
