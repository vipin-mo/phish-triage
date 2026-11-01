"""Run a set of Claude requests through the Message Batches API under the project's spend cap.

Shared by the analyst evaluations. Same money rules as `llm_classifier.py`: the worst case (counted input tokens +
`max_tokens` per request) plus everything already spent must stay under `LLM_MAX_SPEND_USD`, and the real cost of
every batch goes to the spend ledger. A batch that was submitted but not collected is resumed, never resent.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from phish_triage.config import max_llm_spend_usd
from phish_triage.models.llm_classifier import LLM_DIR, check_budget, cost_usd, record_spend, worst_case_usd


def estimate_input_tokens(params: dict[str, dict], client=None, calibrate: int = 20) -> int:
    """Input tokens for all requests: counted on a few with the (free) token-counting API, then scaled by length."""
    chars = {i: len(p["system"][0]["text"]) + len(p["messages"][0]["content"]) for i, p in params.items()}
    per_char = 1 / 3
    if client is not None:
        sample = list(params)[:calibrate]
        counted = sum(
            client.messages.count_tokens(
                **{k: params[i][k] for k in ("model", "system", "messages", "output_config")}
            ).input_tokens
            for i in sample
        )
        per_char = counted / sum(chars[i] for i in sample)
    return int(sum(chars.values()) * per_char * 1.1)


def worst_case(params: dict[str, dict], client=None) -> float:
    model = next(iter(params.values()))["model"]
    max_tokens = next(iter(params.values()))["max_tokens"]
    tokens = estimate_input_tokens(params, client)
    scale = max_tokens / 512  # worst_case_usd assumes llm_classifier's 512-token cap per request
    output_part = worst_case_usd(model, 0, len(params), batch=True) * scale
    return worst_case_usd(model, tokens, 0, batch=True) + output_part


def load_saved(name: str) -> dict[str, dict]:
    saved = LLM_DIR / f"{name}.responses.jsonl"
    rows = [json.loads(line) for line in saved.read_text().splitlines() if line.strip()]
    return {row.pop("id"): row for row in rows}


def run(name: str, params: dict[str, dict], client, poll_seconds: int = 30) -> dict[str, dict]:
    """custom_id -> {"text": str | None, "stop_reason": str, "error": str | None}; records the real cost."""
    from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
    from anthropic.types.messages.batch_create_params import Request

    model = next(iter(params.values()))["model"]
    state = LLM_DIR / f"{name}.batch.json"
    saved = LLM_DIR / f"{name}.responses.jsonl"
    if saved.exists():  # already collected and paid for: never fetch or record it again
        return load_saved(name)
    if state.exists():
        batch_id = json.loads(state.read_text())["batch_id"]
        print(f"{name}: resuming batch {batch_id}", file=sys.stderr)
    else:
        worst = worst_case(params, client)
        check_budget(worst, max_llm_spend_usd())
        batch = client.messages.batches.create(
            requests=[Request(custom_id=i, params=MessageCreateParamsNonStreaming(**p)) for i, p in params.items()]
        )
        batch_id = batch.id
        LLM_DIR.mkdir(parents=True, exist_ok=True)
        state.write_text(json.dumps({"batch_id": batch_id, "worst_case_usd": worst}) + "\n")
        print(f"{name}: submitted {batch_id} ({len(params)} requests, worst case ${worst:.2f})", file=sys.stderr)

    while (batch := client.messages.batches.retrieve(batch_id)).processing_status != "ended":
        print(f"  {batch.processing_status}: {batch.request_counts.processing} processing", file=sys.stderr)
        time.sleep(poll_seconds)

    out, cost = {}, 0.0
    for result in client.messages.batches.results(batch_id):
        if result.result.type != "succeeded":
            out[result.custom_id] = {"text": None, "stop_reason": None, "error": result.result.type}
            continue
        message = result.result.message
        cost += cost_usd(model, message.usage, batch=True)
        text = next((b.text for b in message.content if b.type == "text"), None)
        error = None
        if message.stop_reason == "refusal":
            category = getattr(message.stop_details, "category", None) if message.stop_details else None
            error = f"refusal ({category})"
        elif message.stop_reason == "max_tokens":
            error = "max_tokens"
        out[result.custom_id] = {"text": text, "stop_reason": message.stop_reason, "error": error}
    record_spend({"run": name, "batch_id": batch_id, "model": model, "requests": len(out), "cost_usd": cost})
    Path(LLM_DIR / f"{name}.responses.jsonl").write_text(
        "".join(json.dumps({"id": i, **r}) + "\n" for i, r in out.items())
    )
    return out
