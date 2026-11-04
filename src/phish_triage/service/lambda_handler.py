"""The Lambda entry point: the FastAPI app behind API Gateway (through Mangum).

The image holds the bundle at `PHISH_BUNDLE_DIR` (default /opt/bundle). It is loaded on the first scan of a cold
start, or by the warm-up ping, not at import, so a health check stays fast. With `PHISH_TABLE_PREFIX` set (it is
on Lambda), keys, verdicts and feedback live in DynamoDB; without it, in memory, which refuses every key.

**Explanations run on demand** (`POST /v1/explain`, `service/explain.py`), in the request itself: the add-on sends
the email again when I ask, so no queue has to carry it and nothing is stored. The queue and worker built in Phase 5
for a background design were removed: they would have had to hold the email.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from mangum import Mangum

from phish_triage.service.api import create_app
from phish_triage.service.store import MemoryStore

logging.getLogger().setLevel(logging.INFO)
BUNDLE_DIR = Path(os.environ.get("PHISH_BUNDLE_DIR", "/opt/bundle"))


def _scanner():
    from phish_triage.service.scanner import Scanner

    return Scanner(BUNDLE_DIR)


def _store():
    prefix = os.environ.get("PHISH_TABLE_PREFIX")
    if not prefix:
        return MemoryStore()
    from phish_triage.service.store_dynamo import DynamoStore

    return DynamoStore(prefix)


app = create_app(_scanner, _store())
_http = Mangum(app, lifespan="off")


def handler(event, context):
    """API Gateway requests go to the app. The scheduled warm-up ping (EventBridge, infra/service) only loads the
    model, so a scan seldom waits for a cold start (about 20 s to load, a minute on a new image)."""
    if event.get("source") == "aws.events":
        scanner = app.state.load_scanner()
        return {"warm": True, "model_version": scanner.version}
    return _http(event, context)
