import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location("real_use", Path(__file__).parents[1] / "scripts" / "real_use.py")
real_use = importlib.util.module_from_spec(spec)
spec.loader.exec_module(real_use)


class FakeDynamo:
    def __init__(self, tables):
        self.tables = tables

    def scan(self, TableName, **kwargs):
        return {"Items": self.tables[TableName]}


def test_test_scans_and_older_models_are_left_out_and_only_counts_come_out(monkeypatch):
    from phish_triage.service.store import scan_id

    fixture = scan_id((Path("tests/fixtures") / "spoofed_brand.eml").read_bytes())
    verdicts = [
        {"scan_id": "a" * 64, "verdict": "safe", "stage": "distilbert", "model_version": "with-newsletters-1"},
        {"scan_id": "b" * 64, "verdict": "phish", "stage": "distilbert", "model_version": "with-newsletters-1"},
        {"scan_id": fixture, "verdict": "phish", "stage": "distilbert", "model_version": "with-newsletters-1"},
        {"scan_id": "c" * 64, "verdict": "phish", "stage": "stacked", "model_version": "with-inbox-20261104-4ee04857"},
    ]
    tables = {
        "phish-triage-verdicts": [{"verdict": {"S": json.dumps(v)}, "owner": {"S": "vipin"}} for v in verdicts]
        + [{"verdict": {"S": json.dumps(verdicts[0] | {"scan_id": "d" * 64})}, "owner": {"S": "loadtest"}}],
        "phish-triage-feedback": [
            {"scan_id": {"S": "b" * 64}, "label": {"S": "false_alarm"}},
            {"scan_id": {"S": fixture}, "label": {"S": "correct"}},
        ],
    }
    monkeypatch.setattr("phish_triage.data.retraining.read_masked", lambda: {"x": {"label": "legit"}})
    r = real_use.measure(FakeDynamo(tables))
    assert r["emails_scanned"] == 2 and r["test_emails_left_out"] == 3
    assert r["verdicts"] == {"safe": 1, "phish": 1} and r["feedback"] == {"false_alarm": 1}
    assert r["sent_for_retraining"]["pulled"] == {"legit": 1}
    text = real_use.to_markdown(r)
    assert "a" * 64 not in text and "Emails scanned | 2" in text
