"""The HTTP API: FastAPI locally, the same app on Lambda through Mangum (`service/lambda_handler.py`).

    POST /v1/scan                  raw email (.eml bytes or plain text) -> verdict, score and `phishing_above`
    POST /v1/explain               the same email again -> the analyst's explanation and final verdict (on demand)
    POST /v1/feedback              {"scan_id": ..., "label": "correct" | "false_alarm" | "missed_phish"}
    POST /v1/retraining-email      ?label=phish|legit, the email again: kept for retraining (service/retraining.py)
    GET  /v1/health                no key needed; the model version

Every call but health needs an `X-API-Key`. The rules from the threat model: input over 2 MB is refused (rule 11),
the same email returns the same verdict from the same model (its SHA-256 is the scan id; after a new model is
deployed it is scanned again), each key has a per-minute limit, and only the verdict, never the email, is stored
(`service/store.py`). Each request logs one JSON line with a request id, the key's owner, status, verdict and
time taken; no email content is ever logged.

Explanations (`service/explain.py`) run only when asked for, with `PHISH_EXPLANATIONS=on`: the email in the request
goes to Anthropic once and the answer comes straight back; neither is stored. Each key may ask for
`EXPLAIN_PER_DAY` a day, and all keys together may spend `PHISH_DAILY_LLM_USD` a day (default $0.50), on top of
the monthly limit set at Anthropic.

The service keeps an email only when I send it for retraining (`POST /v1/retraining-email`, at most
`RETRAINING_PER_DAY` a day per key): it goes to the private retraining bucket for at most 90 days.
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from collections.abc import Callable

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from phish_triage.service.store import FEEDBACK_LABELS, MemoryStore, Store, scan_id

MAX_BYTES = 2 * 1024 * 1024
PER_MINUTE = 60
EXPLAIN_PER_DAY = 50
RETRAINING_PER_DAY = 20


def retraining_owners() -> set[str]:
    """The keys' owners allowed to send emails for retraining (`infra/retraining-owners`, set by Terraform); none
    when unset, so a key nobody listed can't put emails into the training data."""
    return {o.strip() for o in os.environ.get("PHISH_RETRAINING_OWNERS", "").split(",") if o.strip()}


SPEND_COUNTER = "llm-spend-microusd"  # all keys together, in millionths of a dollar
log = logging.getLogger("phish_triage.api")


class Feedback(BaseModel):
    scan_id: str = Field(pattern=r"^[0-9a-f]{64}$")  # a SHA-256; DynamoDB refuses an empty key with a 500
    label: str


def create_app(
    scanner_factory: Callable[[], object],
    store: Store,
    *,
    explanations: bool | None = None,
    explainer_factory: Callable[[], object] | None = None,
    shadow_factory: Callable[[], object | None] | None = None,
    retraining_factory: Callable[[], object | None] | None = None,
) -> FastAPI:
    """`scanner_factory` is called once, on the first scan, so a cold start doesn't load the model for health; the
    same for `explainer_factory` (it reads the Anthropic key) on the first explanation. `shadow_factory` returns a
    second scanner or None: in shadow mode every new scan is scored by it too, and only the two verdicts, scores and
    model versions are logged; the answer is always the live model's."""
    if explanations is None:
        explanations = os.environ.get("PHISH_EXPLANATIONS", "off") == "on"
    daily_budget_microusd = int(float(os.environ.get("PHISH_DAILY_LLM_USD", "0.50")) * 1e6)
    app = FastAPI(title="phish-triage", docs_url=None, redoc_url=None, openapi_url=None)
    state: dict = {}

    def scanner():
        if "scanner" not in state:
            state["scanner"] = scanner_factory()
        return state["scanner"]

    def shadow():
        if "shadow" not in state:
            state["shadow"] = shadow_factory() if shadow_factory else None
        return state["shadow"]

    def log_shadow(raw: bytes, live) -> None:
        if (other := shadow()) is None:
            return
        try:
            result = other.scan(raw)
            entry = {"verdict": result.verdict, "score": round(result.score, 6), "stage": result.stage}
        except Exception as exc:  # noqa: BLE001 - the shadow never affects the answer
            entry = {"error": type(exc).__name__}
        live_entry = {"verdict": live.verdict, "score": round(live.score, 6), "stage": live.stage}
        log.info(json.dumps({"event": "shadow", "live": live_entry, "shadow": entry, "shadow_version": other.version}))

    def retraining():
        if "retraining" not in state:
            if retraining_factory is not None:
                state["retraining"] = retraining_factory()
            elif bucket := os.environ.get("PHISH_RETRAINING_BUCKET"):
                from phish_triage.service.retraining import S3Retraining

                state["retraining"] = S3Retraining(bucket)
            else:
                state["retraining"] = None
        return state["retraining"]

    def explainer():
        if "explainer" not in state:
            if explainer_factory is None:
                from phish_triage.service.explain import Explainer, anthropic_client

                state["explainer"] = Explainer(anthropic_client())
            else:
                state["explainer"] = explainer_factory()
        return state["explainer"]

    def owner_of(request: Request) -> str:
        owner = store.key_owner(request.headers.get("x-api-key", ""))
        if owner is None:
            raise HTTPException(401, "missing or unknown API key")
        request.state.owner = owner
        if not store.allow(owner, PER_MINUTE):
            raise HTTPException(429, "too many requests; try again in a minute")
        return owner

    app.state.load_scanner = scanner  # the Lambda warm-up ping loads the model without a request

    @app.middleware("http")
    async def json_log(request: Request, call_next):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        started = time.perf_counter()
        request.state.owner, request.state.verdict = None, None
        error = None
        try:
            response = await call_next(request)
        except Exception as exc:  # noqa: BLE001 - logged by type only: a message could quote the email
            error = type(exc).__name__
            response = JSONResponse({"detail": "internal error"}, status_code=500)
        response.headers["x-request-id"] = request_id
        entry = {
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "owner": request.state.owner,
            "verdict": request.state.verdict,
            "ms": round((time.perf_counter() - started) * 1000, 1),
        }
        if error:
            entry["error"] = error
        log.info(json.dumps(entry))
        return response

    @app.get("/v1/health")
    def health():
        version = state["scanner"].version if "scanner" in state else None
        return {"status": "ok", "model_version": version, "explanations": "on" if explanations else "off"}

    async def email_of(request: Request) -> bytes:
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > MAX_BYTES:
            raise HTTPException(413, "email is larger than 2 MB")
        raw = await request.body()
        if len(raw) > MAX_BYTES:
            raise HTTPException(413, "email is larger than 2 MB")
        if not raw.strip():
            raise HTTPException(400, "empty email")
        return raw

    def verdict_of(owner: str, raw: bytes) -> dict:
        scan = scan_id(raw)
        s = scanner()
        cached = store.get_verdict(owner, scan)
        current = (s.version, getattr(s, "rules_version", None))
        if cached is None or (cached.get("model_version"), cached.get("rules_version")) != current:
            # a verdict of an older model or older rules is replaced
            result = s.scan(raw)
            log_shadow(raw, result)
            cached = {
                "scan_id": scan,
                "verdict": result.verdict,
                "score": round(result.score, 6),
                "phishing_above": result.phishing_above,  # the deciding stage's threshold (see `stage`)
                "stage": result.stage,
                "signals": result.signals,
                "sender": result.sender,
                "model_version": s.version,
                "rules_version": current[1],
            }
            store.put_verdict(owner, scan, cached)
        return cached

    @app.post("/v1/scan")
    async def scan(request: Request):
        owner = owner_of(request)
        verdict = verdict_of(owner, await email_of(request))
        request.state.verdict = verdict["verdict"]
        return verdict

    @app.post("/v1/explain")
    async def explain(request: Request):
        owner = owner_of(request)
        if not explanations:
            raise HTTPException(404, "explanations are switched off")
        raw = await email_of(request)
        from phish_triage.service.explain import worst_case_microusd

        if store.add_today(SPEND_COUNTER, 0) >= daily_budget_microusd:  # before a key's daily count is used up
            raise HTTPException(429, "today's LLM budget is used up; the scan verdict still works")
        if store.add_today(f"explain#{owner}", 1) > EXPLAIN_PER_DAY:
            raise HTTPException(429, f"at most {EXPLAIN_PER_DAY} explanations a day per key")
        # The worst case is reserved first, in one atomic step, and settled to the real cost afterwards: two
        # explanations running at once can't both pass a check and then both spend.
        reserved = worst_case_microusd()
        if store.add_today(SPEND_COUNTER, reserved) > daily_budget_microusd:
            store.add_today(SPEND_COUNTER, -reserved)
            raise HTTPException(429, "today's LLM budget is used up; the scan verdict still works")
        spent = 0
        try:
            verdict = verdict_of(owner, raw)
            model = scanner()
            result = explainer().explain(raw, verdict, getattr(model, "ranks", None), getattr(model, "reader", 1))
            spent = round(result.cost_usd * 1e6)
        finally:
            store.add_today(SPEND_COUNTER, spent - reserved)
        request.state.verdict = result.body["verdict"]
        return result.body

    @app.post("/v1/retraining-email")
    async def retraining_email(request: Request, label: str):
        from phish_triage.service.retraining import KEEP_DAYS, LABELS

        owner = owner_of(request)
        if owner not in retraining_owners():
            raise HTTPException(403, "this key can't send emails for retraining")
        if label not in LABELS:
            raise HTTPException(422, f"label must be one of {', '.join(LABELS)}")
        if (sink := retraining()) is None:
            raise HTTPException(404, "retraining storage is off")
        raw = await email_of(request)
        if store.add_today(f"retraining#{owner}", 1) > RETRAINING_PER_DAY:
            raise HTTPException(429, f"at most {RETRAINING_PER_DAY} emails a day per key")
        verdict = verdict_of(owner, raw)  # stored with the email: what the model said about it
        sink.put(owner, raw, label, verdict)
        request.state.verdict = verdict["verdict"]
        return {"status": "stored", "scan_id": verdict["scan_id"], "label": label, "deleted_after_days": KEEP_DAYS}

    @app.post("/v1/feedback")
    def feedback(body: Feedback, request: Request):
        owner = owner_of(request)
        if body.label not in FEEDBACK_LABELS:
            raise HTTPException(422, f"label must be one of {', '.join(FEEDBACK_LABELS)}")
        verdict = store.get_verdict(owner, body.scan_id)
        if verdict is None:
            raise HTTPException(404, "no scan with this id for this key")
        store.put_feedback(owner, body.scan_id, body.label, verdict.get("model_version"))
        return {"status": "recorded"}

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    return app


def local_app() -> FastAPI:
    """`make serve`: the latest local bundle, an in-memory store and one key printed at start."""
    from phish_triage.service.bundle import latest
    from phish_triage.service.scanner import Scanner

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    store = MemoryStore()
    print(f"API key for this run: {store.add_key('local')}", flush=True)
    return create_app(lambda: Scanner(latest()), store)
