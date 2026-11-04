from fastapi.testclient import TestClient

from phish_triage.service import api
from phish_triage.service.retraining import S3Retraining, key_of
from phish_triage.service.scanner import ScanResult
from phish_triage.service.store import MemoryStore, scan_id

EMAIL = b"From: Bank <alerts@bank.example>\nTo: me@example.com\nSubject: Verify now\n\nZQX-secret-body verify here\n"


class Scanner:
    version, rules_version = "v1", 3

    def scan(self, raw):
        return ScanResult("safe", 0.2, "distilbert", False, False)


class Sink:
    def __init__(self):
        self.kept = []

    def put(self, owner, raw, label, verdict):
        self.kept.append((owner, raw, label, verdict["verdict"]))


def _client(sink, store=None):
    store = store or MemoryStore()
    key = store.add_key("tester")
    app = api.create_app(Scanner, store, explanations=False, retraining_factory=lambda: sink)
    return TestClient(app), key, store


def test_an_email_is_kept_only_when_sent_with_a_label():
    sink = Sink()
    c, key, store = _client(sink)
    assert c.post("/v1/scan", content=EMAIL, headers={"x-api-key": key}).status_code == 200
    assert sink.kept == []  # scanning keeps nothing
    r = c.post("/v1/retraining-email?label=phish", content=EMAIL, headers={"x-api-key": key})
    assert r.status_code == 200 and r.json() == {
        "status": "stored",
        "scan_id": scan_id(EMAIL),
        "label": "phish",
        "deleted_after_days": 90,
    }
    assert sink.kept == [("tester", EMAIL, "phish", "safe")]  # the label I gave, and what the model said
    assert c.post("/v1/retraining-email?label=maybe", content=EMAIL, headers={"x-api-key": key}).status_code == 422
    assert c.post("/v1/retraining-email?label=legit", content=EMAIL).status_code == 401
    assert len(sink.kept) == 1


def test_storage_off_and_the_daily_limit(monkeypatch):
    c, key, _ = _client(None)
    assert c.post("/v1/retraining-email?label=legit", content=EMAIL, headers={"x-api-key": key}).status_code == 404
    monkeypatch.setattr(api, "RETRAINING_PER_DAY", 1)
    sink = Sink()
    c, key, _ = _client(sink)
    codes = [
        c.post("/v1/retraining-email?label=legit", content=EMAIL, headers={"x-api-key": key}).status_code for _ in "ab"
    ]
    assert codes == [200, 429] and len(sink.kept) == 1


class FakeS3:
    def __init__(self):
        self.objects = {}

    def put_object(self, **kwargs):
        self.objects[kwargs["Key"]] = kwargs


def test_the_s3_writer_keeps_the_email_its_label_and_the_verdict():
    s3 = FakeS3()
    verdict = {"scan_id": "a" * 64, "verdict": "safe", "model_version": "m1"}
    key = S3Retraining("bucket", s3).put("vipin", EMAIL, "phish", verdict)
    assert key == key_of("vipin", "a" * 64) == f"emails/vipin/{'a' * 64}.eml"
    stored = s3.objects[key]
    assert stored["Body"] == EMAIL and stored["ContentType"] == "message/rfc822"
    assert stored["Metadata"] == {"label": "phish", "scan-verdict": "safe", "model-version": "m1"}
