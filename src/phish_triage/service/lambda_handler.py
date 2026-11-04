"""The Lambda entry points: the FastAPI app behind API Gateway (through Mangum), and the explanation worker.

The image holds the bundle at `PHISH_BUNDLE_DIR` (default /opt/bundle). It is loaded on the first scan of a cold
start, or by the warm-up ping, not at import, so a health check stays fast. With `PHISH_TABLE_PREFIX` set (it is
on Lambda), keys, verdicts and feedback live in DynamoDB; without it, in memory, which refuses every key.

**Explanations are switched off.** The queue, its dead-letter queue and the `explain` function exist
(infra/main.tf), but the queue's trigger is disabled, the scan never queues anything and no Anthropic key is in
AWS. What the queue would carry is still open: the service keeps no email, so a message would have to carry the
PII-masked text the analyst is shown. That is decided before the explanations are turned on.
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


def explain(event, context):
    """The explanation worker, switched off: a message that reaches it anyway is refused, so it goes to the
    dead-letter queue instead of being dropped."""
    if os.environ.get("PHISH_EXPLANATIONS", "off") != "on":
        raise RuntimeError("explanations are switched off")
    raise NotImplementedError("the explanation worker is built when explanations are turned on (Phase 6)")
