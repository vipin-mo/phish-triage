import json
import logging

import pytest
from fastapi.testclient import TestClient

from phish_triage.service import api
from phish_triage.service.scanner import ScanResult
from phish_triage.service.store import MemoryStore, scan_id

EMAIL = b"From: Bank <alerts@bank.example>\nTo: me@example.com\nSubject: Verify now\n\nZQX-secret-body verify here\n"


class FakeScanner:
    version = "test-1"

    def __init__(self):
        self.calls = 0

    def scan(self, raw: bytes) -> ScanResult:
        self.calls += 1
        return ScanResult("phish", 0.97, "stacked", True, False, ["A signal"], {"verdict": "none", "warnings": []})


@pytest.fixture
def client():
    store, scanner = MemoryStore(), FakeScanner()
    key = store.add_key("tester")
    app = api.create_app(lambda: scanner, store, explanations=False)
    return TestClient(app), key, store, scanner


def test_scan_needs_a_key_and_returns_a_verdict(client):
    c, key, store, _ = client
    assert c.post("/v1/scan", content=EMAIL).status_code == 401
    assert c.post("/v1/scan", content=EMAIL, headers={"x-api-key": "pt_wrong"}).status_code == 401
    r = c.post("/v1/scan", content=EMAIL, headers={"x-api-key": key})
    assert r.status_code == 200 and r.json()["verdict"] == "phish" and r.json()["explanation_id"] is None
    assert r.json()["scan_id"] == scan_id(EMAIL) and r.headers["x-request-id"]
    assert key not in json.dumps(store.keys)  # only the hash is kept


def test_the_same_email_returns_the_same_verdict_without_scanning_again(client):
    c, key, _, scanner = client
    first = c.post("/v1/scan", content=EMAIL, headers={"x-api-key": key}).json()
    second = c.post("/v1/scan", content=EMAIL, headers={"x-api-key": key}).json()
    assert first == second and scanner.calls == 1


def test_large_and_empty_emails_are_refused(client):
    c, key, _, scanner = client
    big = b"x" * (api.MAX_BYTES + 1)
    assert c.post("/v1/scan", content=big, headers={"x-api-key": key}).status_code == 413
    assert c.post("/v1/scan", content=b"  \n", headers={"x-api-key": key}).status_code == 400
    assert scanner.calls == 0


def test_the_store_never_holds_the_email(client):
    c, key, store, _ = client
    c.post("/v1/scan", content=EMAIL, headers={"x-api-key": key})
    assert "ZQX-secret-body" not in json.dumps(list(store.verdicts.values()))


def test_feedback_must_name_a_scan_of_this_key(client):
    c, key, store, _ = client
    other = store.add_key("someone else")
    scan = c.post("/v1/scan", content=EMAIL, headers={"x-api-key": key}).json()["scan_id"]

    def send(label: str, api_key: str) -> int:
        body = {"scan_id": scan, "label": label}
        return c.post("/v1/feedback", json=body, headers={"x-api-key": api_key}).status_code

    assert send("maybe", key) == 422
    assert send("correct", other) == 404
    assert send("false_alarm", key) == 200
    assert store.feedback[0]["label"] == "false_alarm" and store.feedback[0]["owner"] == "tester"


def test_explanations_say_they_are_off(client):
    c, key, _, _ = client
    r = c.get("/v1/explanations/abc", headers={"x-api-key": key})
    assert r.status_code == 404 and "switched off" in r.json()["detail"]
    assert c.get("/v1/health").json()["explanations"] == "off"


def test_rate_limit_per_key(client, monkeypatch):
    c, key, _, _ = client
    monkeypatch.setattr(api, "PER_MINUTE", 2)
    codes = [c.post("/v1/scan", content=EMAIL, headers={"x-api-key": key}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_the_log_line_has_no_email_content(client, caplog):
    c, key, _, _ = client
    with caplog.at_level(logging.INFO, logger="phish_triage.api"):
        c.post("/v1/scan", content=EMAIL, headers={"x-api-key": key})
    line = json.loads(caplog.records[-1].getMessage())
    assert line["verdict"] == "phish" and line["owner"] == "tester" and line["status"] == 200
    assert "ZQX" not in caplog.text and "Verify now" not in caplog.text and key not in caplog.text


def test_the_warm_up_ping_loads_the_model_without_a_request(monkeypatch):
    import importlib

    monkeypatch.delenv("PHISH_TABLE_PREFIX", raising=False)
    from phish_triage.service import lambda_handler

    importlib.reload(lambda_handler)
    monkeypatch.setattr(lambda_handler, "_scanner", lambda: FakeScanner())
    lambda_handler.app = api.create_app(lambda: FakeScanner(), MemoryStore())
    assert lambda_handler.handler({"source": "aws.events"}, None) == {"warm": True, "model_version": "test-1"}
