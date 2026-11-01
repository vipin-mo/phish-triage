"""Saved predictions: every model's validation and test scores per split, so reports are rebuilt without retraining.

    data/predictions/<split>/<model>.json   {"model", "split", "val": {"ids", "scores"}, "test": {"ids", "scores"}}

They hold email ids and scores only, never content, and live under data/ (never committed). `make eval` reads them
all and writes docs/RESULTS.md.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np

PREDICTIONS_DIR = Path("data/predictions")


@dataclass
class Predictions:
    model: str
    split: str
    val_ids: list[str]
    val_scores: np.ndarray
    test_ids: list[str]
    test_scores: np.ndarray
    extra: dict | None = None  # anything else worth keeping (cost, latency, epochs)


def path_for(split: str, model: str, root: Path = PREDICTIONS_DIR) -> Path:
    return root / split.replace("/", "__") / f"{model}.json"


def save(p: Predictions, root: Path = PREDICTIONS_DIR) -> Path:
    path = path_for(p.split, p.model, root)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = {
        "model": p.model,
        "split": p.split,
        "val": {"ids": list(p.val_ids), "scores": [float(s) for s in p.val_scores]},
        "test": {"ids": list(p.test_ids), "scores": [float(s) for s in p.test_scores]},
        "extra": p.extra or {},
    }
    path.write_text(json.dumps(body) + "\n")
    return path


def load(split: str, model: str, root: Path = PREDICTIONS_DIR) -> Predictions:
    body = json.loads(path_for(split, model, root).read_text())
    return Predictions(
        body["model"],
        body["split"],
        body["val"]["ids"],
        np.array(body["val"]["scores"]),
        body["test"]["ids"],
        np.array(body["test"]["scores"]),
        body.get("extra") or None,
    )


def available(root: Path = PREDICTIONS_DIR) -> dict[str, list[str]]:
    """Split -> models with saved predictions."""
    found: dict[str, list[str]] = {}
    for path in sorted(root.glob("*/*.json")):
        found.setdefault(path.parent.name.replace("__", "/"), []).append(path.stem)
    return found
