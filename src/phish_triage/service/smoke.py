"""A check a new version must pass before it gets any traffic (the CodeDeploy hook in `lambda_handler`).

With my traffic, a 10% canary for 10 minutes may see no request at all, so the alarms alone can't judge a new
version. Before any traffic moves, the hook invokes the new version with `{"source": "phish-triage.smoke"}`, and it
scans two hand-made test emails (tests/fixtures, copied into the image at /opt/smoke by `make deploy-image`): a
spoofed brand must come back phish and a clean newsletter safe, with the model in the version's own bundle. Any
other answer, or an error, stops the deployment before it starts.
"""

from __future__ import annotations

import os
from pathlib import Path

SMOKE_DIR = Path(os.environ.get("PHISH_SMOKE_DIR", "/opt/smoke"))
EXPECTED = {"spoofed_brand.eml": "phish", "clean_newsletter.eml": "safe"}


def run(scanner, folder: Path = SMOKE_DIR) -> dict:
    results = {}
    for name, expected in EXPECTED.items():
        path = folder / name
        got = scanner.scan(path.read_bytes()).verdict if path.exists() else "missing"
        results[name] = {"expected": expected, "got": got}
    passed = all(r["expected"] == r["got"] for r in results.values())
    return {"passed": passed, "model_version": scanner.version, "results": results}
