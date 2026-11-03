"""The deployable model bundle: everything the service loads, in one folder, checked against the evaluation.

    python -m phish_triage.service.bundle    # or `make bundle` (after `make train-with-inbox`)

The deployed cascade is the `with_inbox` split's (reports/with_inbox.md): the stacked model (TF-IDF text score +
gradient-boosted trees on the structured features) decides what it is sure about, DistilBERT int8 the rest. The
evaluation scripts fit the stacked model in memory and never save it, so this fits it once more on the same
training data (every step is seeded, so it is the same model) and writes, to artifacts/bundle/<version>/:

- `stacked.joblib`: the TF-IDF vectorizer, its logistic regression and the stacked trees;
- `distilbert.onnx` and `tokenizer.json`: DistilBERT (ONNX fp32) and its tokenizer, served with onnxruntime and
  the `tokenizers` library (no torch, no transformers);
- `tranco.csv`: the pinned domain-popularity list the features use;
- `bundle.json`: the cascade's cutoffs and DistilBERT's threshold (both chosen on validation, as in the
  evaluation), the little-text rule, library versions, the evaluation numbers it must reproduce, and a SHA-256
  of every file, checked on load.

Before writing `bundle.json`, the bundle is loaded the way the service loads it and run on the evaluation's test
emails; it must flag exactly as many of the inbox's test senders' emails and catch exactly as many public-test
phishing emails as reports/with_inbox.json says, or the export stops.

**Why fp32, not int8.** The int8 model was made with dynamic quantization, which picks its scales from the whole
batch, so an email's score depends on the emails scored with it. The evaluation scored in batches and the service
scores one email at a time, and the first export failed this parity check by one inbox email. fp32 gives the same
score either way and matches the PyTorch scores the evaluation uses. Lambda runs this as a container image (up to
10 GB), so int8's smaller size, the reason it existed, isn't needed. The export measures both and writes
reports/bundle.md.

The bundle is trained partly on my private inbox, so it is never committed and never published; it goes to a
private S3 bucket (Phase 5).
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
DISTILBERT_SOURCE = Path("artifacts/distilbert_with_inbox")
FILES = ("stacked.joblib", "distilbert.onnx", "tokenizer.json", "tranco.csv")
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


def export(root: Path = BUNDLE_ROOT) -> Path:
    import joblib
    import onnxruntime
    import sklearn

    from phish_triage.data import inbox
    from phish_triage.evaluation import metrics, predictions
    from phish_triage.evaluation.cascade import choose_cutoffs
    from phish_triage.features.domains import TRANCO_PATH, default_ranks
    from phish_triage.features.extract import matrix
    from phish_triage.models.baselines import email_text, fit_all
    from phish_triage.service import triage

    split, slices = inbox.load_split()
    eval_ids = list(dict.fromkeys(slices["public_test"] + slices["inbox_test"]))
    ids = set(split["train"]) | set(split["val"]) | set(eval_ids)
    records = inbox.read_split_records(ids)
    ranks = default_ranks()

    def part(which: list[str]):
        rows = [records[i] for i in which]
        return [email_text(r) for r in rows], matrix(rows, ranks), np.array([int(r["label"] == "phish") for r in rows])

    train, val = part(split["train"]), part(split["val"])
    fitted = fit_all(*train, *val)
    stacked_val = fitted.scores(val[0], val[1])["stacked"]
    distilbert = predictions.load(inbox.SPLIT, "distilbert_head")
    if distilbert.val_ids != split["val"]:
        raise SystemExit("saved DistilBERT predictions don't match the with_inbox validation split; re-run training")
    cutoffs = choose_cutoffs(val[2], stacked_val)
    threshold = metrics.threshold_at_fpr(val[2], distilbert.val_scores, TARGET_FPR)

    version = f"with-inbox-{datetime.now(UTC):%Y%m%d}-{sha256(DISTILBERT_SOURCE / 'model.onnx')[:8]}"
    folder = root / version
    folder.mkdir(parents=True, exist_ok=True)
    joblib.dump({"text": fitted.text, "stacked": fitted.stacked}, folder / "stacked.joblib")
    shutil.copyfile(DISTILBERT_SOURCE / "model.onnx", folder / "distilbert.onnx")
    shutil.copyfile(DISTILBERT_SOURCE / "pytorch" / "tokenizer.json", folder / "tokenizer.json")
    shutil.copyfile(TRANCO_PATH, folder / "tranco.csv")

    report = json.loads(Path("reports/with_inbox.json").read_text())["after"]["cascade"]
    expected = {
        "inbox_test_flagged": report["inbox_fpr"]["flagged"],
        "public_recall": report["public_recall"],
    }
    config = {
        "version": version,
        "created": datetime.now(UTC).isoformat(timespec="seconds"),
        "split": inbox.SPLIT,
        "stage1_cutoffs": {"low": cutoffs.low, "high": cutoffs.high},
        "distilbert_threshold": threshold,
        "distilbert_strategy": "head",
        "little_text_words": triage.LITTLE_TEXT_WORDS,
        "libraries": {"scikit-learn": sklearn.__version__, "onnxruntime": onnxruntime.__version__},
        "expected": expected,
        "sha256": {name: sha256(folder / name) for name in FILES},
    }
    (folder / BUNDLE_FILE).write_text(json.dumps(config, indent=1) + "\n")

    measured = parity(folder, records, slices)
    print(f"parity: {measured} (expected {expected})", file=sys.stderr)
    if measured["inbox_test_flagged"] != expected["inbox_test_flagged"] or not np.isclose(
        measured["public_recall"], expected["public_recall"]
    ):
        (folder / BUNDLE_FILE).unlink()
        raise SystemExit("the bundle doesn't reproduce reports/with_inbox.json; bundle.json removed")
    texts = [email_text(records[i]) for i in slices["inbox_test"]]
    batch = {
        "fp32": batch_dependence(folder / "distilbert.onnx", folder / "tokenizer.json", texts),
        "int8": batch_dependence(DISTILBERT_SOURCE / "model.int8.onnx", folder / "tokenizer.json", texts),
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
    return "\n".join(
        [
            "# The deployable bundle",
            "",
            f"Generated by `make bundle`. Version `{config['version']}`, trained on the `{config['split']}` split. The "
            "bundle itself is private (it is trained partly on my inbox); this page has only its settings and checks.",
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
            "**Parity with reports/with_inbox.md**, run the way the service runs it (one email at a time): "
            f"{measured['inbox_test_flagged']} of the inbox test senders' emails flagged (report: "
            f"{config['expected']['inbox_test_flagged']}), public-test recall {measured['public_recall']:.4f} "
            f"(report: {config['expected']['public_recall']:.4f}).",
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
    return {
        "inbox_test_flagged": sum(cascade(i) for i in slices["inbox_test"]),
        "public_recall": float(np.mean([cascade(i) for i in public_phish])),
    }


def latest(root: Path = BUNDLE_ROOT) -> Path:
    found = sorted(p for p in root.glob("*") if (p / BUNDLE_FILE).exists())
    if not found:
        raise SystemExit(f"no bundle in {root}; run `make bundle`")
    return found[-1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.parse_args(argv)
    folder = export()
    print(folder)
    return 0


if __name__ == "__main__":
    sys.exit(main())
