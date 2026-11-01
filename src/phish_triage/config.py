"""Settings read from the environment, with values from a local `.env` file filled in (never committed)."""

from __future__ import annotations

import os
from pathlib import Path

ENV_FILE = Path(".env")


def load_env(path: Path = ENV_FILE) -> None:
    """Copy KEY=VALUE lines from `.env` into the environment; variables already set are left alone."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if value.strip():
            os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


def max_llm_spend_usd() -> float:
    """Hard cap on total LLM spend for this project's evaluation runs, enforced in code."""
    load_env()
    return float(os.environ.get("LLM_MAX_SPEND_USD", "2.00"))
