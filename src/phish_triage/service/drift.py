"""The weekly drift check: has the mail I scan, as the deployed model sees it, moved away from what it was tested on?

A weekly EventBridge rule runs `handler` (infra/service). It reads the last 7 days of stored verdicts (score, deciding
stage, sender-check result; never an email) and compares three distributions with a reference, by the population
stability index (PSI): the scores in fixed bins, the share each stage decides, and the sender-check results.

**The reference** (`drift_reference.json`, written by `scripts/drift_reference.py`) is the deployed bundle's verdicts
on legitimate mail it never trained on: my test inbox's held-out senders. Until 2026-11-12 it also had PrivacyMail's
held-out websites (3,987 emails in all); the first full week of real use alarmed on all three distributions against
that mix, and two of them came from the mix itself (PrivacyMail's sender results are a third "partial", my Gmail's
all "pass"), so after that first reading the reference became the test inbox alone, the mail closest to mine. Not
the training data: that is about half phishing, and the mail I scan is almost all legitimate, so the class mix alone
would read as drift every week. Only bin counts are kept, and the gate fails if the reference was made with another
bundle than `infra/bundle-version`.

**The rule, set before the first run:** a PSI above 0.25 in any of the three (the usual reading: under 0.1 stable,
0.1 to 0.25 a moderate shift, above 0.25 a major one) raises the `drift` alarm. A week with fewer than 30 scans is
reported as not enough data and publishes no number.
"""

from __future__ import annotations

import json
import math
import time
from collections import Counter
from pathlib import Path

REFERENCE = Path(__file__).with_name("drift_reference.json")
PSI_LIMIT = 0.25
MIN_SCANS = 30
WINDOW_DAYS = 7
# Fixed bins on the log-odds of the score: the scores crowd near 0 and 1, where quantile bins would collapse.
LOGIT_EDGES = (-8.0, -6.0, -4.0, -2.0, 0.0, 2.0, 4.0, 6.0, 8.0)
STAGES = ("stacked", "distilbert")
SENDER = ("pass", "partial", "fail", "none")
EPSILON = 1e-4  # an empty bin counts as this share, so the log stays finite


def score_bin(score: float) -> int:
    p = min(max(score, 1e-12), 1 - 1e-12)
    logit = math.log(p / (1 - p))
    return sum(logit >= edge for edge in LOGIT_EDGES)


def distributions(verdicts: list[dict]) -> dict[str, list[int]]:
    """Bin counts of the three distributions the check compares."""
    scores = Counter(score_bin(v["score"]) for v in verdicts)
    stages = Counter(v.get("stage") for v in verdicts)
    sender = Counter((v.get("sender") or {}).get("verdict") for v in verdicts)
    return {
        "score": [scores[i] for i in range(len(LOGIT_EDGES) + 1)],
        "stage": [stages[s] for s in STAGES],
        "sender": [sender[s] for s in SENDER],
    }


def psi(reference: list[int], live: list[int]) -> float:
    ref_total, live_total = sum(reference), sum(live)
    total = 0.0
    for r, x in zip(reference, live, strict=True):
        a, b = max(r / ref_total, EPSILON), max(x / live_total, EPSILON)
        total += (b - a) * math.log(b / a)
    return total


def compare(reference: dict, verdicts: list[dict], model_version: str | None = None) -> dict:
    result: dict = {"scans": len(verdicts), "reference_bundle": reference["bundle"], "limit": PSI_LIMIT}
    if model_version and model_version != reference["bundle"]:
        return result | {"status": "stale reference", "detail": f"the scans are of {model_version}"}
    if len(verdicts) < MIN_SCANS:
        return result | {"status": "not enough data", "detail": f"fewer than {MIN_SCANS} scans this week"}
    live = distributions(verdicts)
    values = {name: round(psi(reference["counts"][name], live[name]), 4) for name in live}
    result |= {"psi": values, "max_psi": max(values.values())}
    return result | {"status": "drift" if result["max_psi"] > PSI_LIMIT else "stable"}


def recent_verdicts(db, table: str, days: int = WINDOW_DAYS, now: float | None = None) -> list[dict]:
    """The stored verdicts (`store_dynamo.put_verdict`) of the last `days`, read with a paginated scan."""
    since = int((now or time.time()) - days * 86_400)
    found, start = [], None
    while True:
        kwargs = {
            "TableName": table,
            "FilterExpression": "created >= :since",
            "ExpressionAttributeValues": {":since": {"N": str(since)}},
            "ProjectionExpression": "verdict",
        }
        if start:
            kwargs["ExclusiveStartKey"] = start
        page = db.scan(**kwargs)
        found += [json.loads(item["verdict"]["S"]) for item in page.get("Items", [])]
        if not (start := page.get("LastEvaluatedKey")):
            return found


def handler(event, context, db=None, cloudwatch=None):
    """The weekly run: compare, log the result (no email, no scan id) and publish the numbers to CloudWatch."""
    import logging
    import os

    import boto3

    db = db or boto3.client("dynamodb")
    cloudwatch = cloudwatch or boto3.client("cloudwatch")
    reference = json.loads(REFERENCE.read_text())
    bundle = Path(os.environ.get("PHISH_BUNDLE_DIR", "/opt/bundle")) / "bundle.json"
    deployed = json.loads(bundle.read_text())["version"]  # the image's own bundle, the one serving traffic
    verdicts = recent_verdicts(db, f"{os.environ.get('PHISH_TABLE_PREFIX', 'phish-triage')}-verdicts")
    current = [v for v in verdicts if v.get("model_version") == deployed]
    result = compare(reference, current, deployed)
    result["other_bundles"] = len(verdicts) - len(current)
    logging.getLogger().setLevel(logging.INFO)
    logging.info(json.dumps({"event": "drift", **result}))
    metrics = [{"MetricName": "Scans", "Value": len(current), "Unit": "Count"}]
    if "max_psi" in result:
        metrics.append({"MetricName": "MaxPSI", "Value": result["max_psi"], "Unit": "None"})
    cloudwatch.put_metric_data(Namespace="phish-triage/drift", MetricData=metrics)
    return result
