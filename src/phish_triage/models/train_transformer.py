"""Fine-tune DistilBERT on the splits, save its predictions, and export the deployable model to ONNX int8.

    python -m phish_triage.models.train_transformer                        # head strategy, every split
    python -m phish_triage.models.train_transformer random by_time --strategy head_tail

For each split: fine-tune on `train`, keep the epoch with the best validation ROC AUC, and save validation and test
scores to data/predictions/ as `distilbert_<strategy>`. Runs are logged to MLflow (mlruns/mlflow.db; browse with
`uv run --group train mlflow ui --backend-store-uri sqlite:///mlruns/mlflow.db`).

The `random` split's head model is exported to ONNX, quantized to int8, and measured for size, CPU latency and the
accuracy change from quantizing (reports/onnx.json, reports/onnx.md). The private `with_inbox` split (`random` plus
part of my test inbox, see `data/inbox.py`) is trained and exported the same way, to artifacts/distilbert_with_inbox/
and reports/onnx_with_inbox.*, only when asked for by name; its records never leave data/private/.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import numpy as np

from phish_triage.data import inbox
from phish_triage.data.splits import SPLITS_DIR
from phish_triage.evaluation import metrics, predictions
from phish_triage.models import transformer
from phish_triage.models.baselines import email_text

SPLITS = (
    "random",
    "by_source/nazario_to_phishing_pot",
    "by_source/phishing_pot_to_nazario",
    "by_time",
    "by_time_nazario",
    "old_era",
)
EXPORT_SPLIT = "random"
PRIVATE_SPLITS = (inbox.SPLIT,)  # trained only when named
ARTIFACTS_DIR = Path("artifacts")
REPORTS_DIR = Path("reports")
MLFLOW_URI = "sqlite:///mlruns/mlflow.db"
LATENCY_EMAILS = 300


def run_split(name: str, splits: dict, config: transformer.TrainConfig, tokenizer, mlflow) -> dict:
    parts = splits[name]
    records = inbox.read_split_records({i for part in parts.values() for i in part})
    data = {}
    for part, ids in parts.items():
        texts = [email_text(records[i]) for i in ids]
        data[part] = (ids, texts, transformer.encode(tokenizer, texts, config.strategy), _labels(records, ids))
    model_name = f"distilbert_{config.strategy}"

    with mlflow.start_run(run_name=f"{model_name} {name}"):
        mlflow.log_params({**config.__dict__, "split": name, "model": transformer.MODEL_NAME})
        mlflow.log_param("revision", transformer.MODEL_REVISION)
        result = transformer.train(
            data["train"][2],
            data["train"][3],
            data["val"][2],
            data["val"][3],
            config,
            tokenizer.pad_token_id,
            log=lambda values, step: mlflow.log_metrics(values, step=step),
        )
        scores = {
            part: transformer.predict_torch(result.model, data[part][2], tokenizer.pad_token_id)
            for part in ("val", "test")
        }
        threshold = metrics.threshold_at_fpr(data["val"][3], scores["val"], 0.01)
        test_recall, test_fpr = metrics.rates_at_threshold(data["test"][3], scores["test"], threshold)
        summary = {
            "best_epoch": result.best_epoch,
            "train_minutes": result.seconds / 60,
            "test_recall_at_1pct_fpr": metrics.recall_at_fpr(data["test"][3], scores["test"], 0.01),
            "test_recall_at_0.1pct_fpr": metrics.recall_at_fpr(data["test"][3], scores["test"], 0.001),
            "test_fpr_at_val_threshold": test_fpr,
            "test_recall_at_val_threshold": test_recall,
        }
        mlflow.log_metrics({k.replace("%", "pct"): float(v) for k, v in summary.items()})
        predictions.save(
            predictions.Predictions(
                model_name,
                name,
                data["val"][0],
                scores["val"],
                data["test"][0],
                scores["test"],
                {"history": result.history, **summary},
            )
        )
        print(f"{name} {model_name}: {json.dumps({k: round(v, 4) for k, v in summary.items()})}", file=sys.stderr)
        if name in (EXPORT_SPLIT, *PRIVATE_SPLITS) and config.strategy == "head":
            onnx_report = export_and_measure(result.model, tokenizer, data, scores["test"], name)
            mlflow.log_metrics({f"onnx_{k}": v for k, v in _flatten(onnx_report).items()})
    return summary


def export_and_measure(model, tokenizer, data: dict, torch_test_scores: np.ndarray, split: str = EXPORT_SPLIT) -> dict:
    """ONNX fp32 and int8: file size, single-email CPU latency, and test metrics vs the PyTorch model."""
    suffix = "" if split == EXPORT_SPLIT else f"_{split}"
    out_dir = ARTIFACTS_DIR / f"distilbert{suffix}"
    model.save_pretrained(out_dir / "pytorch")
    tokenizer.save_pretrained(out_dir / "pytorch")
    fp32 = transformer.export_onnx(model, out_dir / "model.onnx")
    int8 = transformer.quantize_int8(fp32, out_dir / "model.int8.onnx")

    test_ids, test_texts, test_tokens, y_test = data["test"]
    val_ids, _, val_tokens, y_val = data["val"]
    rng = np.random.default_rng(transformer.SEED)
    sample = [test_texts[i] for i in rng.choice(len(test_texts), min(LATENCY_EMAILS, len(test_texts)), replace=False)]
    report: dict = {"torch": _quality(y_test, torch_test_scores)}
    for label, path in (("onnx_fp32", fp32), ("onnx_int8", int8)):
        classifier = transformer.OnnxClassifier(path, tokenizer, threads=1)
        test_scores = classifier.scores_from_ids(test_tokens)
        report[label] = {
            "megabytes": round(path.stat().st_size / 1e6, 1),
            "latency_ms_1_thread": transformer.latency_ms(classifier, sample),
            "max_abs_score_change_vs_torch": float(np.abs(test_scores - torch_test_scores).max()),
            **_quality(y_test, test_scores),
        }
        if label == "onnx_int8":
            predictions.save(
                predictions.Predictions(
                    "distilbert_head_int8",
                    split,
                    val_ids,
                    classifier.scores_from_ids(val_tokens),
                    test_ids,
                    test_scores,
                    {"megabytes": report[label]["megabytes"], "latency_ms": report[label]["latency_ms_1_thread"]},
                )
            )
    REPORTS_DIR.mkdir(exist_ok=True)
    (REPORTS_DIR / f"onnx{suffix}.json").write_text(json.dumps(report, indent=1) + "\n")
    (REPORTS_DIR / f"onnx{suffix}.md").write_text(onnx_markdown(report, split))
    print(onnx_markdown(report, split), file=sys.stderr)
    return report


def _quality(y: np.ndarray, scores: np.ndarray) -> dict:
    from sklearn.metrics import roc_auc_score

    return {
        "roc_auc": float(roc_auc_score(y, scores)),
        "recall_at_1pct_fpr": metrics.recall_at_fpr(y, scores, 0.01),
        "recall_at_0.1pct_fpr": metrics.recall_at_fpr(y, scores, 0.001),
    }


def onnx_markdown(r: dict, split: str = EXPORT_SPLIT) -> str:
    command = "make train-transformer" if split == EXPORT_SPLIT else "make train-with-inbox"
    lines = [
        "# DistilBERT: PyTorch vs ONNX vs ONNX int8",
        "",
        f"Generated by `{command}`. The `{split}` split's model; latency is one email at a time on one "
        f"CPU thread, tokenization included, over {LATENCY_EMAILS} test emails.",
        "",
        "| Version | Size (MB) | Latency p50 (ms) | Latency p95 (ms) | ROC AUC | Recall @ 1% FPR | Recall @ 0.1% FPR | "
        "Largest score change |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
        f"| PyTorch | | | | {r['torch']['roc_auc']:.4f} | {r['torch']['recall_at_1pct_fpr']:.3f} | "
        f"{r['torch']['recall_at_0.1pct_fpr']:.3f} | |",
    ]
    for label, name in (("onnx_fp32", "ONNX fp32"), ("onnx_int8", "ONNX int8")):
        v = r[label]
        lines.append(
            f"| {name} | {v['megabytes']:.0f} | {v['latency_ms_1_thread']['p50']:.1f} | "
            f"{v['latency_ms_1_thread']['p95']:.1f} | {v['roc_auc']:.4f} | {v['recall_at_1pct_fpr']:.3f} | "
            f"{v['recall_at_0.1pct_fpr']:.3f} | {v['max_abs_score_change_vs_torch']:.4f} |"
        )
    return "\n".join(lines) + "\n"


def _labels(records: dict, ids: list[str]) -> np.ndarray:
    return np.array([int(records[i]["label"] == "phish") for i in ids])


def _flatten(report: dict, prefix: str = "") -> dict[str, float]:
    flat = {}
    for key, value in report.items():
        name = f"{prefix}{key}".replace("%", "pct").replace(".", "_")
        if isinstance(value, dict):
            flat |= _flatten(value, name + "_")
        elif isinstance(value, int | float):
            flat[name] = float(value)
    return flat


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("splits", nargs="*", help=f"any of: {', '.join(SPLITS + PRIVATE_SPLITS)} (default: public)")
    parser.add_argument("--strategy", choices=transformer.STRATEGIES, default="head")
    parser.add_argument("--epochs", type=int, default=2)
    args = parser.parse_args(argv)
    if unknown := set(args.splits) - set(SPLITS + PRIVATE_SPLITS):
        parser.error(f"unknown split(s): {', '.join(sorted(unknown))}")

    os.environ.setdefault("MLFLOW_DISABLE_AGENT_HINT", "1")
    import mlflow

    Path("mlruns").mkdir(exist_ok=True)
    mlflow.set_tracking_uri(MLFLOW_URI)
    mlflow.set_experiment("distilbert")
    splits = json.loads((SPLITS_DIR / "splits.json").read_text())
    if set(args.splits) & set(PRIVATE_SPLITS):
        splits[inbox.SPLIT] = inbox.load_split()[0]
    tokenizer = transformer.load_tokenizer()
    config = transformer.TrainConfig(strategy=args.strategy, epochs=args.epochs)
    for name in args.splits or list(SPLITS):
        run_split(name, splits, config, tokenizer, mlflow)
    return 0


if __name__ == "__main__":
    sys.exit(main())
