"""DistilBERT fine-tuned as a phishing classifier, then exported to ONNX and quantized to int8 for serving.

Two ways to fit an email into DistilBERT's 512 tokens are compared, rather than argued about:

- `head`: the first 510 tokens (subject first, so it is always included);
- `head_tail`: the first 255 and the last 255 tokens, because phishing often puts the link, the signature or
  the "act now" line at the end.

Training uses PyTorch on Apple's GPU (MPS) when available, else CUDA, else CPU. Serving uses onnxruntime on CPU
only (no torch), which is what runs on Lambda.
"""

from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

MODEL_NAME = "distilbert/distilbert-base-uncased"
MODEL_REVISION = "12040accade4e8a0f71eabdb258fecc2e7e948be"  # pinned; Apache-2.0
MAX_TOKENS = 512
STRATEGIES = ("head", "head_tail")
SEED = 20261029


def load_tokenizer():
    from transformers import AutoTokenizer

    return AutoTokenizer.from_pretrained(MODEL_NAME, revision=MODEL_REVISION)


def encode(tokenizer, texts: list[str], strategy: str = "head", max_tokens: int = MAX_TOKENS) -> list[list[int]]:
    """Token ids with [CLS] ... [SEP], cut to `max_tokens` by keeping the head, or the head and the tail."""
    if strategy not in STRATEGIES:
        raise ValueError(f"strategy must be one of {STRATEGIES}")
    budget = max_tokens - 2
    encoded = []
    for ids in tokenizer(texts, add_special_tokens=False, truncation=False)["input_ids"]:
        if len(ids) > budget:
            ids = ids[:budget] if strategy == "head" else ids[: budget // 2] + ids[-(budget - budget // 2) :]
        encoded.append([tokenizer.cls_token_id, *ids, tokenizer.sep_token_id])
    return encoded


def pad(batch: list[list[int]], pad_id: int) -> tuple[np.ndarray, np.ndarray]:
    """Pad to the longest sequence in the batch (not to 512), with the matching attention mask."""
    width = max(len(ids) for ids in batch)
    input_ids = np.full((len(batch), width), pad_id, dtype=np.int64)
    mask = np.zeros((len(batch), width), dtype=np.int64)
    for i, ids in enumerate(batch):
        input_ids[i, : len(ids)] = ids
        mask[i, : len(ids)] = 1
    return input_ids, mask


def device():
    import torch

    if torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cuda" if torch.cuda.is_available() else "cpu")


@dataclass
class TrainConfig:
    strategy: str = "head"
    epochs: int = 2
    learning_rate: float = 5e-5
    batch_size: int = 16
    warmup_share: float = 0.06
    weight_decay: float = 0.01
    seed: int = SEED


@dataclass
class TrainResult:
    model: object
    best_epoch: int
    history: list[dict] = field(default_factory=list)
    seconds: float = 0.0


def train(
    train_ids: list[list[int]],
    y_train: np.ndarray,
    val_ids: list[list[int]],
    y_val: np.ndarray,
    config: TrainConfig,
    pad_id: int,
    log=None,
) -> TrainResult:
    """Fine-tune, keep the epoch with the best validation ROC AUC. `log(metrics, step)` receives progress."""
    import torch
    from sklearn.metrics import roc_auc_score
    from transformers import AutoModelForSequenceClassification, get_linear_schedule_with_warmup

    from phish_triage.evaluation.metrics import recall_at_fpr

    random.seed(config.seed)
    np.random.seed(config.seed)
    torch.manual_seed(config.seed)
    run_on = device()
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, revision=MODEL_REVISION, num_labels=2)
    model.to(run_on)
    decay = [p for n, p in model.named_parameters() if not any(k in n for k in ("bias", "LayerNorm", "layer_norm"))]
    no_decay = [p for n, p in model.named_parameters() if any(k in n for k in ("bias", "LayerNorm", "layer_norm"))]
    optimizer = torch.optim.AdamW(
        [{"params": decay, "weight_decay": config.weight_decay}, {"params": no_decay, "weight_decay": 0.0}],
        lr=config.learning_rate,
    )
    steps_per_epoch = math.ceil(len(train_ids) / config.batch_size)
    total = steps_per_epoch * config.epochs
    schedule = get_linear_schedule_with_warmup(optimizer, int(total * config.warmup_share), total)

    rng = np.random.default_rng(config.seed)
    best_auc, best_epoch, best_state, history = -1.0, 0, None, []
    started = time.time()
    for epoch in range(1, config.epochs + 1):
        model.train()
        order = rng.permutation(len(train_ids))
        running = 0.0
        for step, start in enumerate(range(0, len(order), config.batch_size), 1):
            members = order[start : start + config.batch_size]
            input_ids, mask = pad([train_ids[i] for i in members], pad_id)
            out = model(
                input_ids=torch.from_numpy(input_ids).to(run_on),
                attention_mask=torch.from_numpy(mask).to(run_on),
                labels=torch.from_numpy(y_train[members]).long().to(run_on),
            )
            out.loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            schedule.step()
            optimizer.zero_grad()
            running += out.loss.item()
            if log and step % 100 == 0:
                log({"train_loss": running / 100}, (epoch - 1) * steps_per_epoch + step)
                running = 0.0
        val_scores = predict_torch(model, val_ids, pad_id)
        metrics = {
            "epoch": epoch,
            "val_auc": float(roc_auc_score(y_val, val_scores)),
            "val_recall_at_1pct_fpr": recall_at_fpr(y_val, val_scores, 0.01),
            "minutes": (time.time() - started) / 60,
        }
        history.append(metrics)
        if log:
            log({k: v for k, v in metrics.items() if k != "epoch"}, epoch * steps_per_epoch)
        if metrics["val_auc"] > best_auc:
            best_auc, best_epoch = metrics["val_auc"], epoch
            best_state = {k: v.detach().to("cpu").clone() for k, v in model.state_dict().items()}
    model.load_state_dict(best_state)
    return TrainResult(model, best_epoch, history, time.time() - started)


def predict_torch(model, ids: list[list[int]], pad_id: int, batch_size: int = 64) -> np.ndarray:
    """Phishing probabilities. Emails are sorted by length so each batch pads as little as possible."""
    import torch

    run_on = next(model.parameters()).device
    model.eval()
    order = np.argsort([len(x) for x in ids])
    scores = np.empty(len(ids), dtype=np.float64)
    with torch.no_grad():
        for start in range(0, len(order), batch_size):
            members = order[start : start + batch_size]
            input_ids, mask = pad([ids[i] for i in members], pad_id)
            logits = model(
                input_ids=torch.from_numpy(input_ids).to(run_on), attention_mask=torch.from_numpy(mask).to(run_on)
            ).logits
            scores[members] = torch.softmax(logits.float(), dim=-1)[:, 1].cpu().numpy()
    return scores


def export_onnx(model, path: Path) -> Path:
    """Export to ONNX with a dynamic batch size and sequence length (CPU, fp32)."""
    import torch

    model = model.to("cpu").eval()
    path.parent.mkdir(parents=True, exist_ok=True)
    example = (torch.ones(1, 16, dtype=torch.long), torch.ones(1, 16, dtype=torch.long))
    torch.onnx.export(
        model,
        example,
        str(path),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={"input_ids": {0: "batch", 1: "tokens"}, "attention_mask": {0: "batch", 1: "tokens"}},
        opset_version=17,
        dynamo=False,
    )
    return path


def quantize_int8(fp32_path: Path, int8_path: Path) -> Path:
    """Dynamic int8 quantization of the weights (activations stay float); no calibration data needed."""
    from onnxruntime.quantization import QuantType, quantize_dynamic

    quantize_dynamic(str(fp32_path), str(int8_path), weight_type=QuantType.QInt8)
    return int8_path


class OnnxClassifier:
    """Serving-side scorer: tokenizer + onnxruntime on CPU. No torch needed."""

    def __init__(self, path: Path, tokenizer=None, strategy: str = "head", threads: int = 1):
        import onnxruntime as ort

        options = ort.SessionOptions()
        options.intra_op_num_threads = threads
        options.inter_op_num_threads = 1
        self.session = ort.InferenceSession(str(path), options, providers=["CPUExecutionProvider"])
        self.tokenizer = tokenizer or load_tokenizer()
        self.strategy = strategy

    def scores_from_ids(self, ids: list[list[int]], batch_size: int = 32) -> np.ndarray:
        order = np.argsort([len(x) for x in ids])
        scores = np.empty(len(ids), dtype=np.float64)
        for start in range(0, len(order), batch_size):
            members = order[start : start + batch_size]
            input_ids, mask = pad([ids[i] for i in members], self.tokenizer.pad_token_id)
            logits = self.session.run(["logits"], {"input_ids": input_ids, "attention_mask": mask})[0]
            exp = np.exp(logits - logits.max(axis=1, keepdims=True))
            scores[members] = exp[:, 1] / exp.sum(axis=1)
        return scores

    def score(self, texts: list[str]) -> np.ndarray:
        return self.scores_from_ids(encode(self.tokenizer, texts, self.strategy))


def latency_ms(classifier: OnnxClassifier, texts: list[str]) -> dict[str, float]:
    """Per-email latency, one email at a time, including tokenization: p50 / p95 / mean in milliseconds."""
    timings = []
    for text in texts:
        started = time.perf_counter()
        classifier.score([text])
        timings.append((time.perf_counter() - started) * 1000)
    return {
        "p50": float(np.percentile(timings, 50)),
        "p95": float(np.percentile(timings, 95)),
        "mean": float(np.mean(timings)),
        "emails": len(texts),
    }
