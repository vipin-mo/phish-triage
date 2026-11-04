import boto3
import pytest
from moto import mock_aws

from phish_triage.service.store import hash_key
from phish_triage.service.store_dynamo import DynamoStore

# The same keys as infra/main.tf
TABLES = {
    "keys": [("key_hash", "S")],
    "verdicts": [("owner", "S"), ("scan_id", "S")],
    "feedback": [("owner", "S"), ("scan_at", "S")],
    "rate": [("owner", "S"), ("minute", "N")],
}


@pytest.fixture
def store(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-2")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    with mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-2")
        for name, keys in TABLES.items():
            client.create_table(
                TableName=f"pt-{name}",
                KeySchema=[
                    {"AttributeName": k, "KeyType": t}
                    for (k, _), t in zip(keys, ("HASH", "RANGE")[: len(keys)], strict=True)
                ],
                AttributeDefinitions=[{"AttributeName": k, "AttributeType": kind} for k, kind in keys],
                BillingMode="PAY_PER_REQUEST",
            )
        yield DynamoStore("pt", client=client), client


def test_keys_verdicts_feedback_and_rate_round_trip(store):
    s, client = store
    s.add_key_hash(hash_key("pt_secret"), "vipin")
    assert s.key_owner("pt_secret") == "vipin" and s.key_owner("pt_other") is None
    stored = client.scan(TableName="pt-keys")["Items"][0]
    assert "pt_secret" not in str(stored)  # only the hash

    assert s.get_verdict("vipin", "abc") is None
    s.put_verdict("vipin", "abc", {"verdict": "phish", "score": 0.9})
    assert s.get_verdict("vipin", "abc") == {"verdict": "phish", "score": 0.9}
    assert s.get_verdict("someone", "abc") is None

    s.put_feedback("vipin", "abc", "false_alarm")
    s.put_feedback("vipin", "abc", "correct", "with-newsletters-1")
    items = client.scan(TableName="pt-feedback")["Items"]
    versions = sorted(i.get("model_version", {}).get("S", "") for i in items)
    assert len(items) == 2 and versions == ["", "with-newsletters-1"]

    assert [s.allow("vipin", 2) for _ in range(3)] == [True, True, False]


def test_a_key_hash_cannot_be_overwritten(store):
    s, _ = store
    s.add_key_hash("h", "vipin")
    with pytest.raises(Exception, match="ConditionalCheckFailed"):
        s.add_key_hash("h", "someone else")
