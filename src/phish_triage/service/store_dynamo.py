"""The store on DynamoDB: the same four things as `MemoryStore`, in four on-demand tables (infra/main.tf).

- `<prefix>-keys`: key hash -> owner. Keys are added with `python -m phish_triage.service.keys`.
- `<prefix>-verdicts`: (owner, scan id) -> the verdict JSON. No email content.
- `<prefix>-feedback`: (owner, scan id + time) -> label.
- `<prefix>-rate`: (owner, minute) -> request count, removed by DynamoDB's TTL after a few minutes.
"""

from __future__ import annotations

import json
import time
import uuid

RATE_TTL_SECONDS = 300
VERDICT_DAYS = 90  # a stored verdict (the scan id, never the email) is deleted after this; infra/service sets the TTL


class DynamoStore:
    def __init__(self, prefix: str, client=None):
        import boto3

        self._db = client or boto3.client("dynamodb")
        self.keys, self.verdicts = f"{prefix}-keys", f"{prefix}-verdicts"
        self.feedback, self.rate = f"{prefix}-feedback", f"{prefix}-rate"

    def add_key_hash(self, key_hash: str, owner: str) -> None:
        self._db.put_item(
            TableName=self.keys,
            Item={"key_hash": {"S": key_hash}, "owner": {"S": owner}, "created": {"N": str(int(time.time()))}},
            ConditionExpression="attribute_not_exists(key_hash)",
        )

    def key_owner(self, api_key: str) -> str | None:
        from phish_triage.service.store import hash_key

        item = self._db.get_item(TableName=self.keys, Key={"key_hash": {"S": hash_key(api_key)}}).get("Item")
        return item["owner"]["S"] if item else None

    def allow(self, owner: str, per_minute: int) -> bool:
        minute = int(time.time() // 60)
        result = self._db.update_item(
            TableName=self.rate,
            Key={"owner": {"S": owner}, "minute": {"N": str(minute)}},
            UpdateExpression="ADD requests :one SET expires = :expires",
            ExpressionAttributeValues={":one": {"N": "1"}, ":expires": {"N": str(minute * 60 + RATE_TTL_SECONDS)}},
            ReturnValues="UPDATED_NEW",
        )
        return int(result["Attributes"]["requests"]["N"]) <= per_minute

    def get_verdict(self, owner: str, scan: str) -> dict | None:
        key = {"owner": {"S": owner}, "scan_id": {"S": scan}}
        item = self._db.get_item(TableName=self.verdicts, Key=key).get("Item")
        return json.loads(item["verdict"]["S"]) if item else None

    def put_verdict(self, owner: str, scan: str, verdict: dict) -> None:
        self._db.put_item(
            TableName=self.verdicts,
            Item={
                "owner": {"S": owner},
                "scan_id": {"S": scan},
                "verdict": {"S": json.dumps(verdict)},
                "created": {"N": str(int(time.time()))},
                "expires": {"N": str(int(time.time()) + VERDICT_DAYS * 86_400)},  # DynamoDB deletes it then (TTL)
            },
        )

    def put_feedback(self, owner: str, scan: str, label: str, model_version: str | None = None) -> None:
        now = time.time()
        item = {
            "owner": {"S": owner},
            "scan_at": {"S": f"{scan}#{now:.3f}#{uuid.uuid4().hex[:8]}"},  # two in one ms stay two
            "scan_id": {"S": scan},
            "label": {"S": label},
            "at": {"N": str(int(now))},
        }
        if model_version:
            item["model_version"] = {"S": model_version}
        self._db.put_item(TableName=self.feedback, Item=item)
