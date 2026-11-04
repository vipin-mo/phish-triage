"""The deployable model bundle: everything the service loads, in one folder, checked against the evaluation.

    python -m phish_triage.service.bundle    # or `make bundle` (after `make train-with-newsletters`)

The deployed cascade is the `with_newsletters` split's (reports/with_inbox.md, the *newsletters* setup): my inbox
and PrivacyMail newsletters added to the public training data. It replaced the `with_inbox` split's, which flagged
76.5% of PrivacyMail's newsletters (reports/privacymail.md); `--split with_inbox` still builds that one. The stacked
model (TF-IDF text score + gradient-boosted trees on the structured features) decides what it is sure about,
DistilBERT the rest. The
evaluation scripts fit the stacked model in memory and never save it, so this fits it once more on the same
training data (every step is seeded, so it is the same model) and writes, to artifacts/bundle/<version>/:

- `stacked.joblib`: the TF-IDF vectorizer, its logistic regression and the stacked trees;
- `distilbert.onnx` and `tokenizer.json`: DistilBERT (ONNX fp32) and its tokenizer, served with onnxruntime and
  the `tokenizers` library (no torch, no transformers);
- `domain_ranks.json`: the pinned domain-popularity list the features use, as the finished lookup table (reading
  the CSV took 8 s of a Lambda cold start);
- `bundle.json`: the cascade's cutoffs and DistilBERT's threshold (both chosen on validation, as in the
  evaluation), the little-text rule, library versions, the evaluation numbers it must reproduce, and a SHA-256
  of every file, checked on load.

Before writing `bundle.json`, the bundle is loaded the way the service loads it and run on the evaluation's test
emails; it must flag exactly as many of the inbox's test senders' emails (and of the PrivacyMail websites held out
of training) and catch exactly as many public-test phishing emails as reports/with_inbox.json says, or the export
stops.

**Why fp32, not int8.** The int8 model was made with dynamic quantization, which picks its scales from the whole
batch, so an email's score depends on the emails scored with it. The evaluation scored in batches and the service
scores one email at a time, and the first export failed this parity check by one inbox email. fp32 gives the same
score either way and matches the PyTorch scores the evaluation uses. Lambda runs this as a container image (up to
10 GB), so int8's smaller size, the reason it existed, isn't needed. The export measures both and writes
reports/bundle.md.

The bundle is trained partly on my private inbox and on PrivacyMail, so it is never committed and never published;
it goes to a private S3 bucket and image registry (Phase 5). PrivacyMail's owner allows models trained on it to be
used and published; only the newsletters themselves can't be shared.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

import numpy as np

BUNDLE_ROOT = Path("artifacts/bundle")
BUNDLE_FILE = "bundle.json"
DEPLOYED_SPLIT = "with_newsletters"
# split -> (its DistilBERT, its setup in reports/with_inbox.json, which the bundle must reproduce)
SOURCES = {
    "with_inbox": (Path("artifacts/distilbert_with_inbox"), "after"),
    "with_newsletters": (Path("artifacts/distilbert_with_newsletters"), "newsletters"),
}
FILES = ("stacked.joblib", "distilbert.onnx", "tokenizer.json", "domain_ranks.json")
REPORT = Path("reports/bundle.md")
TARGET_FPR = 0.01


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def verify(folder: Path) -> dict:
    """The bundle's settings, after checking every file against its recorded SHA-256."""
    config = json.loads((folder / BUNDLE_FILE).read_text())
    for name, expected in config["sha256"].items():
        if sha256(folder / name) != expected:
            raise ValueError(f"{name} does not match bundle.json; the bundle is damaged or was changed")
    return config


def load_split(name: str) -> tuple[dict[str, list[str]], dict]:
    """The split and its test slices; `with_newsletters` adds the held-out PrivacyMail websites to the inbox's."""
    from phish_triage.data import inbox, privacymail

    split, slices = inbox.load_split()
    if name == privacymail.NEWSLETTER_SPLIT:
        split, extra = privacymail.load_split()
        slices = slices | extra
    check_public_test_unseen(split["train"] + split["val"])
    return split, slices


def check_public_test_unseen(trained_on: list[str]) -> None:
    """The analyst and injection evaluations test on the current `random` split, but the private splits froze their
    copy of its training part when they were built: rebuilding splits.json (a masking fix, a re-download) reshuffles
    it, and its new test emails could be ones the deployed model trained on. Stop instead of measuring on them."""
    from phish_triage.data.splits import SPLITS_DIR

    test = set(json.loads((SPLITS_DIR / "splits.json").read_text())["random"]["test"])
    if overlap := len(test & set(trained_on)):
        raise SystemExit(f"{overlap} `random` test emails are in the deployed split's training data; rebuild it")


def export(split_name: str = DEPLOYED_SPLIT, root: Path = BUNDLE_ROOT) -> Path:
    import joblib
    import onnxruntime
    import sklearn

    from phish_triage.data import inbox
    from phish_triage.evaluation import metrics, predictions
    from phish_triage.evaluation.cascade import choose_cutoffs
    from phish_triage.features.domains import default_ranks
    from phish_triage.features.extract import matrix
    from phish_triage.models.baselines import email_text, fit_all
    from phish_triage.service import triage

    source, setup = SOURCES[split_name]
    split, slices = load_split(split_name)
    eval_ids = list(dict.fromkeys(slices["public_test"] + slices["inbox_test"] + slices.get("privacymail_test", [])))
    ids = set(split["train"]) | set(split["val"]) | set(eval_ids)
    records = inbox.read_split_records(ids)
    ranks = default_ranks()

    def part(which: list[str]):
        rows = [records[i] for i in which]
        return [email_text(r) for r in rows], matrix(rows, ranks), np.array([int(r["label"] == "phish") for r in rows])

    train, val = part(split["train"]), part(split["val"])
    fitted = fit_all(*train, *val)
    stacked_val = fitted.scores(val[0], val[1])["stacked"]
    distilbert = predictions.load(split_name, "distilbert_head")
    if distilbert.val_ids != split["val"]:
        raise SystemExit(f"saved DistilBERT predictions don't match the {split_name} validation split; re-run training")
    cutoffs = choose_cutoffs(val[2], stacked_val)
    threshold = metrics.threshold_at_fpr(val[2], distilbert.val_scores, TARGET_FPR)

    staging = root / "staging"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    joblib.dump({"text": fitted.text, "stacked": fitted.stacked}, staging / "stacked.joblib")
    shutil.copyfile(source / "model.onnx", staging / "distilbert.onnx")
    shutil.copyfile(source / "pytorch" / "tokenizer.json", staging / "tokenizer.json")
    ranks.save(staging / "domain_ranks.json")
    hashes = {name: sha256(staging / name) for name in FILES}
    # The name changes whenever any file does, so a rebuilt bundle never replaces one that is deployed.
    content = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()[:8]
    version = f"{split_name.replace('_', '-')}-{datetime.now(UTC):%Y%m%d}-{content}"
    folder = root / version
    if folder.exists():
        shutil.rmtree(staging)
        raise SystemExit(f"{folder} already exists with the same content")
    staging.rename(folder)

    report = json.loads(Path("reports/with_inbox.json").read_text())[setup]["cascade"]
    expected = {
        "inbox_test_flagged": report["inbox_fpr"]["flagged"],
        "public_recall": report["public_recall"],
    }
    if "privacymail_test" in slices:
        expected["privacymail_test_flagged"] = report["privacymail_fpr"]["flagged"]
    config = {
        "version": version,
        "created": datetime.now(UTC).isoformat(timespec="seconds"),
        "split": split_name,
        "report_setup": setup,
        "stage1_cutoffs": {"low": cutoffs.low, "high": cutoffs.high},
        "distilbert_threshold": threshold,
        "distilbert_strategy": "head",
        "little_text_words": triage.LITTLE_TEXT_WORDS,
        "libraries": {"scikit-learn": sklearn.__version__, "onnxruntime": onnxruntime.__version__},
        "expected": expected,
        "sha256": hashes,
    }
    (folder / BUNDLE_FILE).write_text(json.dumps(config, indent=1) + "\n")

    measured = parity(folder, records, slices)
    print(f"parity: {measured} (expected {expected})", file=sys.stderr)
    counts_match = all(measured[k] == v for k, v in expected.items() if k.endswith("_flagged"))
    if not counts_match or not np.isclose(measured["public_recall"], expected["public_recall"]):
        (folder / BUNDLE_FILE).unlink()
        raise SystemExit("the bundle doesn't reproduce reports/with_inbox.json; bundle.json removed")
    texts = [email_text(records[i]) for i in slices["inbox_test"]]
    batch = {
        "fp32": batch_dependence(folder / "distilbert.onnx", folder / "tokenizer.json", texts),
        "int8": batch_dependence(source / "model.int8.onnx", folder / "tokenizer.json", texts),
    }
    REPORT.write_text(to_markdown(config, measured, batch, len(texts)))
    return folder


def batch_dependence(model: Path, tokenizer: Path, texts: list[str]) -> float:
    """The largest change in an email's score between scoring it alone and in a batch of 32."""
    from phish_triage.models.transformer import OnnxClassifier, encode
    from phish_triage.service.scanner import FastTokenizer

    fast = FastTokenizer(tokenizer)
    classifier = OnnxClassifier(model, tokenizer=fast, threads=4)
    ids = encode(fast, texts)
    alone = np.array([classifier.scores_from_ids([x])[0] for x in ids])
    return float(np.abs(alone - classifier.scores_from_ids(ids, batch_size=32)).max())


def to_markdown(config: dict, measured: dict, batch: dict[str, float], n: int) -> str:
    cut = config["stage1_cutoffs"]
    expected = config["expected"]
    privacymail = (
        f", {measured['privacymail_test_flagged']} of the held-out PrivacyMail websites' newsletters flagged "
        f"(report: {expected['privacymail_test_flagged']})"
        if "privacymail_test_flagged" in expected
        else ""
    )
    return "\n".join(
        [
            "# The deployable bundle",
            "",
            f"Generated by `make bundle`. Version `{config['version']}`, trained on the `{config['split']}` split. The "
            "bundle itself is private (it is trained partly on my inbox and on PrivacyMail); this page has only its "
            "settings and checks.",
            "",
            "| Setting | Value |",
            "|---|---|",
            f"| Stage 1 (stacked model) decides | below {cut['low']:.4g} safe, above {cut['high']:.4g} phishing |",
            f"| Stage 2 (DistilBERT, ONNX fp32) flags | above {config['distilbert_threshold']:.4g} |",
            f"| Little-text rule | fewer than {config['little_text_words']} visible words with images or attachments "
            "-> review |",
            f"| Libraries | scikit-learn {config['libraries']['scikit-learn']}, onnxruntime "
            f"{config['libraries']['onnxruntime']} |",
            "",
            f"**Parity with reports/with_inbox.md** (the *{config['report_setup']}* setup), run the way the service "
            f"runs it (one email at a time): {measured['inbox_test_flagged']} of the inbox test senders' emails "
            f"flagged (report: {expected['inbox_test_flagged']}){privacymail}, public-test recall "
            f"{measured['public_recall']:.4f} (report: {expected['public_recall']:.4f}).",
            "",
            f"**Score change between one email alone and in a batch of 32** (largest, over the {n} inbox test emails): "
            f"ONNX fp32 {batch['fp32']:.1e}, ONNX int8 {batch['int8']:.3f}. That is why the service uses fp32.",
            "",
        ]
    )


def parity(folder: Path, records: dict, slices: dict) -> dict:
    """Run the bundle as the service does, on the masked test records, and count what the report counts."""
    from phish_triage.service.scanner import Scanner

    scanner = Scanner(folder, threads=4)
    cascade = lambda i: scanner.scan_record(records[i]).cascade_phish  # noqa: E731
    public_phish = [i for i in slices["public_test"] if records[i]["label"] == "phish"]
    measured = {
        "inbox_test_flagged": sum(cascade(i) for i in slices["inbox_test"]),
        "public_recall": float(np.mean([cascade(i) for i in public_phish])),
    }
    if "privacymail_test" in slices:
        measured["privacymail_test_flagged"] = sum(cascade(i) for i in slices["privacymail_test"])
    return measured


def latest(root: Path = BUNDLE_ROOT, split: str | None = None) -> Path:
    """The newest complete bundle (of `split`, if given), by its `created` time (names end in a content hash, so
    they don't sort by age)."""
    found = [p for p in root.glob("*") if (p / BUNDLE_FILE).exists()]
    if split:
        found = [p for p in found if json.loads((p / BUNDLE_FILE).read_text())["split"] == split]
    if not found:
        raise SystemExit(f"no {split or ''} bundle in {root}; run `make bundle`")
    return max(found, key=lambda p: json.loads((p / BUNDLE_FILE).read_text())["created"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--split", choices=sorted(SOURCES), default=DEPLOYED_SPLIT)
    args = parser.parse_args(argv)
    folder = export(args.split)
    print(folder)
    return 0


if __name__ == "__main__":
    sys.exit(main())
