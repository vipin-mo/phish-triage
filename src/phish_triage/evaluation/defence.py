"""Does the defence close the robustness gap, and what does it cost? (Phase 7.2, part 2: reports/defence.md)

    python -m phish_triage.evaluation.defence build      # the two candidate bundles (after `make train-with-attacks`)
    python -m phish_triage.evaluation.defence measure    # every setup on every test ($0; nothing goes to an LLM)

The setups, each run as the service runs a bundle, one email at a time:

- **deployed:** the deployed bundle as it is (reader 1);
- **(a) reader 2:** the deployed bundle's models reading with reader 2 (`features/html.py`, `features/normalize.py`,
  `baselines.body_text`), its cutoffs and threshold unchanged;
- **(b) + stage 1 retrained:** stage 1 fitted on `with_attacks` (`data/attacks.py`) with reader 2, and the deployed
  DistilBERT with its threshold set again on the validation emails read with reader 2;
- **(c) + DistilBERT retrained:** the same stage 1, and a DistilBERT fine-tuned on `with_attacks` with reader 2;
- **(d) reader 2, retrained without copies:** both stages trained on the deployed split's own emails (`with_normalized`
  is `with_retraining` read with reader 2), added after (c) to tell its two changes apart.

The tests: the clean ones every model is measured on (the public test's phishing and legitimate mail, the 2026
phishing, the newsletter-like phishing, my inbox's test senders, PrivacyMail's held-out websites), so the cost of the
defence shows; part 1's attacks on the public test's phishing; the held-out attacks (`robustness.HELD_OUT`), set
before the defence was written; and Greco et al.'s LLM-written phishing. The private tests are scored on this laptop
and only their counts are written.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing
import sys
from pathlib import Path

REPORTS_DIR = Path("reports")
SPLIT = "with_attacks"
CANDIDATES = {  # name -> (its split, its DistilBERT)
    "b_stage1": (SPLIT, Path("artifacts/distilbert_with_newsletters")),
    "c_both": (SPLIT, Path("artifacts/distilbert_with_attacks")),
    "d_normalized": ("with_normalized", Path("artifacts/distilbert_with_normalized")),
}
SETUPS = ("deployed", "a_reader2", "b_stage1", "c_both", "d_normalized", "e_visible")
SETUP_NAMES = {
    "deployed": "Deployed",
    "a_reader2": "(a) Reader 2",
    "b_stage1": "(b) + stage 1 retrained",
    "c_both": "(c) + DistilBERT retrained",
    "d_normalized": "(d) Reader 2, retrained without copies",
    "e_visible": "(e) Reader 3, in service since 2026-11-12",
}
THREADS = 2  # per setup; the four setups run side by side


def build(names: list[str]) -> dict[str, str]:
    """The candidate bundles in `names` that aren't built yet."""
    from phish_triage.service.bundle import CANDIDATE_ROOT, export_candidate

    made = {}
    for name in names:
        split, distilbert = CANDIDATES[name]
        if not (distilbert / "model.onnx").exists():
            raise SystemExit(f"{distilbert}/model.onnx is missing (make train-with-attacks or train-normalized)")
        if built := [p.name for p in (CANDIDATE_ROOT / name).glob("*") if p.is_dir()]:
            print(f"{name}: already built ({built[0]})", file=sys.stderr)
            continue
        made[name] = export_candidate(split, distilbert, name, reader=2).name
        print(f"{name}: {made[name]}", file=sys.stderr)
    return made


def scanner_for(setup: str):
    from phish_triage.service.bundle import CANDIDATE_ROOT, DEPLOYED_SPLIT, latest
    from phish_triage.service.scanner import Scanner

    if setup == "e_visible":  # reader 3 (text-indent, clip, transform; no fake signals block): the bundle in service
        return Scanner(latest(split="with_visible"), threads=THREADS)
    if setup in ("deployed", "a_reader2"):
        return Scanner(latest(split=DEPLOYED_SPLIT), threads=THREADS, reader=2 if setup == "a_reader2" else None)
    (folder,) = [p for p in (CANDIDATE_ROOT / setup).iterdir() if p.is_dir()]
    return Scanner(folder, threads=THREADS)


def test_sets() -> tuple[dict[str, list[str]], dict[str, dict]]:
    """(slice name -> ids, the records): the deployed split's tests, the same for every setup."""
    from phish_triage.data import inbox
    from phish_triage.evaluation.with_inbox import newsletter_like_phish
    from phish_triage.features.domains import default_ranks
    from phish_triage.features.extract import FEATURE_NAMES, extract
    from phish_triage.service.bundle import DEPLOYED_SPLIT, load_split

    _, slices = load_split(DEPLOYED_SPLIT)
    wanted = ("public_test", "phish_2026_test", "inbox_test", "privacymail_test")
    records = inbox.read_split_records({i for name in wanted for i in slices[name]})
    ranks = default_ranks()
    phish_ids = [i for i in slices["public_test"] if records[i]["label"] == "phish"] + slices["phish_2026_test"]
    features = {i: [extract(records[i], ranks)[f] for f in FEATURE_NAMES] for i in phish_ids}
    public = slices["public_test"]
    sets = {
        "public_phish": [i for i in public if records[i]["label"] == "phish"],
        "public_legit": [i for i in public if records[i]["label"] != "phish"],
        "phish_2026": slices["phish_2026_test"],
        "newsletter_like_phish": newsletter_like_phish(features, records, slices),
        "inbox_test": slices["inbox_test"],
        "privacymail_test": slices["privacymail_test"],
    }
    return sets, records


def measure_setup(setup: str) -> dict:
    from phish_triage.data import greco
    from phish_triage.evaluation import robustness as rb

    scanner = scanner_for(setup)
    sets, records = test_sets()
    flagged = lambda record: scanner.scan_record(record).cascade_phish  # noqa: E731
    out: dict = {"bundle": scanner.version, "reader": scanner.reader, "clean": {}, "attacks": {}}
    for name, ids in sets.items():
        out["clean"][name] = {"emails": len(ids), "flagged": sum(flagged(records[i]) for i in ids)}
    public = [records[i] for i in sets["public_phish"]]
    attacks = {k: v for k, v in rb.ATTACKS.items() if k not in ("clean", "hidden_html_style_class_at_end")}
    for name, attack in (attacks | rb.HELD_OUT).items():
        out["attacks"][name] = {"emails": len(public), "flagged": sum(flagged(attack(r)) for r in public)}
        print(f"{setup} {name}: {out['attacks'][name]['flagged']}", file=sys.stderr)
    llm = [r for r in greco.records() if r["label"] == "phish"]
    out["attacks"]["greco_llm_phish"] = {"emails": len(llm), "flagged": sum(flagged(r) for r in llm)}
    return out


def reader_check() -> dict:
    """Emails where reader 1 hides at least 5 words that reader 2 shows. Reader 2 only ever hides more, except that it
    reads a font size with its unit, so these are the emails reader 1 cut ordinary text from (`1em` read as 1 px)."""
    from phish_triage.features.html import visible_html

    sets, records = test_sets()

    def cut(i: str) -> bool:
        html = records[i].get("html") or ""
        return bool(html) and len(visible_html(html, 2).text.split()) >= len(visible_html(html).text.split()) + 5

    return {name: {"emails": len(ids), "flagged": sum(cut(i) for i in ids)} for name, ids in sets.items()}


# --- The report ---


def _share(v: dict) -> str:
    return f"{v['flagged'] / v['emails']:.1%}"


SHORT = {
    "public_phish": "of the public test's phishing",
    "public_legit": "of its legitimate mail",
    "phish_2026": "of the 2026 phishing",
    "newsletter_like_phish": "of the newsletter-like phishing",
    "inbox_test": "of my inbox's test emails",
    "privacymail_test": "of the PrivacyMail ones",
}
CLEAN_ROWS = {
    "public_phish": "Public test, phishing caught",
    "phish_2026": "2026 phishing caught",
    "newsletter_like_phish": "Newsletter-like phishing caught",
    "public_legit": "Public test, legitimate flagged",
    "inbox_test": "My inbox's test senders flagged",
    "privacymail_test": "PrivacyMail held-out websites flagged",
}


def _reader_check(r: dict) -> list[str]:
    if "reader_check" not in r:
        return []
    c = r["reader_check"]
    return [
        "Reader 1 reads a CSS font size without its unit, so text at `1em` or smaller counts as hidden. In these tests "
        "it cut at least 5 visible words from "
        + ", ".join(f"{c[k]['flagged']} of {c[k]['emails']:,} {SHORT[k]}" for k in c)
        + ". Reader 2 reads the unit; the deployed models were trained without that text.",
        "",
    ]


def to_markdown(r: dict) -> str:
    from phish_triage.evaluation.robustness import ATTACKS, HELD_OUT, NAMES

    setups = [s for s in SETUPS if s in r["setups"]]
    header = "| | " + " | ".join(SETUP_NAMES[s] for s in setups) + " |"
    rule = "|---|" + "---:|" * len(setups)

    def row(label: str, group: str, key: str, counts: bool = False) -> str:
        cells = []
        for s in setups:
            v = r["setups"][s][group][key]
            cells.append(f"{v['flagged']} of {v['emails']:,}" if counts else f"{_share(v)}")
        return f"| {label} | " + " | ".join(cells) + " |"

    attacks = list(r["setups"][setups[0]]["attacks"])
    part1, held_out = [a for a in attacks if a in ATTACKS], [a for a in attacks if a in HELD_OUT]
    lines = [
        "# The robustness defence: reader 2 and training on attacked copies",
        "",
        "Generated by `make defence`. Every setup runs as the service runs a bundle, one email at a time; nothing is "
        "deployed by this report. *Deployed* is the bundle in service when it ran (`with-retraining-…`, reader 1; "
        "setup *(d)* has been in service since 2026-11-05); *(a)* the same models reading with reader 2; "
        "*(b)* stage 1 retrained on `with_attacks` (the deployed split plus an attacked copy of each training phishing "
        "email) with reader 2; *(c)* DistilBERT retrained on it too. (b) and (c) change two things at once, what the "
        "models learn from (reader 2's text) and the attacked copies; *(d)*, added afterwards, retrains both stages on "
        "the deployed split's own emails read with reader 2, without copies. The private tests are scored on my "
        "laptop; only counts are shown.",
        "",
        "## The clean tests",
        "",
        header,
        rule,
        *[
            row(label, "clean", key, counts=key in ("newsletter_like_phish", "inbox_test"))
            for key, label in CLEAN_ROWS.items()
        ],
        "",
        *_reader_check(r),
        "## Part 1's attacks on the public test's phishing (caught)",
        "",
        header,
        rule,
        *[row(NAMES[a], "attacks", a) for a in part1],
        "",
        "## Held-out attacks (caught)",
        "",
        "Set before the defence was written (`robustness.HELD_OUT`); reader 2 has no rule written for "
        "`text-indent`, `clip` or `transform`, and no training copy uses any of these.",
        "",
        header,
        rule,
        *[row(NAMES[a], "attacks", a) for a in held_out],
        "",
        "## LLM-written phishing (Greco et al.)",
        "",
        header,
        rule,
        row("Caught", "attacks", "greco_llm_phish"),
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("build", "measure", "reader-check", "report"))
    parser.add_argument("--setups", nargs="*", default=list(SETUPS), choices=SETUPS)
    args = parser.parse_args(argv)
    REPORTS_DIR.mkdir(exist_ok=True)
    path = REPORTS_DIR / "defence.json"
    if args.command == "build":
        print(json.dumps(build([s for s in args.setups if s in CANDIDATES]), indent=1))
        return 0
    if args.command == "reader-check":
        saved = json.loads(path.read_text()) if path.exists() else {"setups": {}}
        path.write_text(json.dumps(saved | {"reader_check": reader_check()}, indent=1) + "\n")
    if args.command == "measure":
        with multiprocessing.get_context("spawn").Pool(len(args.setups)) as pool:
            results = dict(zip(args.setups, pool.map(measure_setup, args.setups), strict=True))
        saved = json.loads(path.read_text()) if path.exists() else {"setups": {}}
        saved["setups"] |= results
        path.write_text(json.dumps(saved, indent=1) + "\n")
    text = to_markdown(json.loads(path.read_text()))
    (REPORTS_DIR / "defence.md").write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
