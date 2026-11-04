"""The HTTP API: FastAPI locally, the same app on Lambda through Mangum (`service/lambda_handler.py`).

    POST /v1/scan                  raw email (.eml bytes or plain text) -> verdict
    GET  /v1/explanations/{id}     the LLM explanation of a scan (switched off for now)
    POST /v1/feedback              {"scan_id": ..., "label": "correct" | "false_alarm" | "missed_phish"}
    GET  /v1/health                no key needed; the model version

Every call but health needs an `X-API-Key`. The rules from the threat model: input over 2 MB is refused (rule 11),
the same email returns the same verdict from the same model (its SHA-256 is the scan id; after a new model is
deployed it is scanned again), each key has a per-minute limit, and only the verdict, never the email, is stored
(`service/store.py`). Each request logs one JSON line with a request id, the key's owner, status, verdict and
time taken; no email content is ever logged.

Explanations are built but switched off (`PHISH_EXPLANATIONS=on` turns them on in a later phase): a scan then
answers `explanation_id: null`, and the explanations endpoint says they are off.
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
from pydantic import BaseModel

from phish_triage.service.store import FEEDBACK_LABELS, MemoryStore, Store, scan_id

MAX_BYTES = 2 * 1024 * 1024
PER_MINUTE = 60
log = logging.getLogger("phish_triage.api")


class Feedback(BaseModel):
    scan_id: str
    label: str


def create_app(scanner_factory: Callable[[], object], store: Store, *, explanations: bool | None = None) -> FastAPI:
    """`scanner_factory` is called once, on the first scan, so a cold start doesn't load the model for health."""
    if explanations is None:
        explanations = os.environ.get("PHISH_EXPLANATIONS", "off") == "on"
    app = FastAPI(title="phish-triage", docs_url=None, redoc_url=None, openapi_url=None)
    state: dict = {}

    def scanner():
        if "scanner" not in state:
            state["scanner"] = scanner_factory()
        return state["scanner"]

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
        response = await call_next(request)
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
        log.info(json.dumps(entry))
        return response

    @app.get("/v1/health")
    def health():
        version = state["scanner"].version if "scanner" in state else None
        return {"status": "ok", "model_version": version, "explanations": "on" if explanations else "off"}

    @app.post("/v1/scan")
    async def scan(request: Request):
        owner = owner_of(request)
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > MAX_BYTES:
            raise HTTPException(413, "email is larger than 2 MB")
        raw = await request.body()
        if len(raw) > MAX_BYTES:
            raise HTTPException(413, "email is larger than 2 MB")
        if not raw.strip():
            raise HTTPException(400, "empty email")
        scan = scan_id(raw)
        s = scanner()
        cached = store.get_verdict(owner, scan)
        if cached is None or cached.get("model_version") != s.version:  # a verdict of an older model is replaced
            result = s.scan(raw)
            cached = {
                "scan_id": scan,
                "verdict": result.verdict,
                "score": round(result.score, 6),
                "stage": result.stage,
                "signals": result.signals,
                "sender": result.sender,
                "model_version": s.version,
                "explanation_id": None,
            }
            store.put_verdict(owner, scan, cached)
        request.state.verdict = cached["verdict"]
        return cached

    @app.get("/v1/explanations/{explanation_id}")
    def explanation(explanation_id: str, request: Request):
        owner_of(request)
        if not explanations:
            raise HTTPException(404, "explanations are switched off")
        raise HTTPException(404, "no such explanation")

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
