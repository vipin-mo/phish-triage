"""The Lambda entry point: the FastAPI app behind API Gateway, through Mangum.

The image holds the bundle at `PHISH_BUNDLE_DIR` (default /opt/bundle). It is loaded on the first scan of a cold
start, not at import, so a health check stays fast. The DynamoDB store replaces the in-memory one with the AWS
setup; until then this handler only serves health and refuses every key.
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


handler = Mangum(create_app(_scanner, MemoryStore()), lifespan="off")
