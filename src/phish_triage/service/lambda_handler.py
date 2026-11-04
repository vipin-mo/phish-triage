"""The Lambda entry points: the FastAPI app behind API Gateway (through Mangum), and the CodeDeploy hook that checks a
new version before it gets traffic (`before_traffic`).

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
# Shadow mode: an image built with SHADOW=<bundle version> also carries that bundle here; every new scan is scored
# by it too and only the two verdicts are logged (service/api.py). An image without one has an empty folder.
SHADOW_DIR = Path(os.environ.get("PHISH_SHADOW_DIR", "/opt/shadow"))


def _scanner():
    from phish_triage.service.scanner import Scanner

    return Scanner(BUNDLE_DIR)


def _shadow():
    from phish_triage.service.bundle import BUNDLE_FILE
    from phish_triage.service.scanner import Scanner

    return Scanner(SHADOW_DIR) if (SHADOW_DIR / BUNDLE_FILE).exists() else None


def _store():
    prefix = os.environ.get("PHISH_TABLE_PREFIX")
    if not prefix:
        return MemoryStore()
    from phish_triage.service.store_dynamo import DynamoStore

    return DynamoStore(prefix)


app = create_app(_scanner, _store(), shadow_factory=_shadow)
_http = Mangum(app, lifespan="off")


def handler(event, context):
    """API Gateway requests go to the app. The scheduled warm-up ping (EventBridge, infra/service) only loads the
    model, so a scan seldom waits for a cold start (about 20 s to load, a minute on a new image)."""
    if event.get("source") == "aws.events":
        scanner = app.state.load_scanner()
        return {"warm": True, "model_version": scanner.version}
    if event.get("source") == "phish-triage.smoke":  # the CodeDeploy hook, below
        from phish_triage.service import smoke

        return smoke.run(app.state.load_scanner())
    return _http(event, context)


def before_traffic(event, context, codedeploy=None, lambda_client=None):
    """CodeDeploy's BeforeAllowTraffic hook (its own small function, infra/service): run the smoke check on the new
    version, which also loads its model, and pass or fail the deployment before any traffic moves."""
    import json

    import boto3
    from botocore.config import Config

    codedeploy = codedeploy or boto3.client("codedeploy")
    lambda_client = lambda_client or boto3.client(
        "lambda", config=Config(read_timeout=200, retries={"max_attempts": 0})
    )
    deployment = codedeploy.get_deployment(deploymentId=event["DeploymentId"])["deploymentInfo"]
    appspec = json.loads(deployment["revision"]["appSpecContent"]["content"])
    target = next(iter(appspec["Resources"][0].values()))["Properties"]
    status = "Failed"
    try:
        answer = lambda_client.invoke(
            FunctionName=target["Name"],
            Qualifier=str(target["TargetVersion"]),
            Payload=json.dumps({"source": "phish-triage.smoke"}).encode(),
        )
        result = json.loads(answer["Payload"].read() or b"{}")
        logging.info(json.dumps({"event": "smoke", "version": target["TargetVersion"], **result}))
        if not answer.get("FunctionError") and result.get("passed"):
            status = "Succeeded"
    except Exception as exc:  # noqa: BLE001 - any failure fails the deployment
        logging.info(json.dumps({"event": "smoke", "version": target["TargetVersion"], "error": type(exc).__name__}))
    codedeploy.put_lifecycle_event_hook_execution_status(
        deploymentId=event["DeploymentId"],
        lifecycleEventHookExecutionId=event["LifecycleEventHookExecutionId"],
        status=status,
    )
    return {"status": status}
