"""Emails I send for retraining: the one case where the service keeps an email, and only when I ask.

`POST /v1/retraining-email?label=phish|legit` (the add-on's "Send as phishing / legitimate" buttons) stores that
email in the private retraining bucket (infra/service: encrypted, no public access, HTTPS only, not versioned, every
object deleted after 90 days), with the label I gave and what the model said. The scan function may only write
there; `make retrain` reads the emails from my laptop and deletes each one once it is used. They are never sent to an
LLM: the retraining step parses them with the source `retraining`, one of the private sources (`data/private.py`).
"""

from __future__ import annotations

LABELS = ("phish", "legit")
PREFIX = "emails/"
KEEP_DAYS = 90


def key_of(owner: str, scan_id: str) -> str:
    return f"{PREFIX}{owner}/{scan_id}.eml"


class S3Retraining:
    def __init__(self, bucket: str, client=None):
        import boto3

        self.bucket = bucket
        self.client = client or boto3.client("s3")

    def put(self, owner: str, raw: bytes, label: str, verdict: dict) -> str:
        key = key_of(owner, verdict["scan_id"])
        self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=raw,
            ContentType="message/rfc822",
            Metadata={
                "label": label,
                "scan-verdict": verdict["verdict"],
                "model-version": verdict["model_version"],
            },
        )
        return key
