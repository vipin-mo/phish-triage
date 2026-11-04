import json

from phish_triage.service import drift


def _verdicts(n, score=0.01, stage="distilbert", sender="pass", version="b1"):
    return [{"score": score, "stage": stage, "sender": {"verdict": sender}, "model_version": version}] * n


REFERENCE = {"bundle": "b1", "counts": drift.distributions(_verdicts(60) + _verdicts(40, stage="stacked"))}


def test_the_same_mix_is_stable_and_a_shift_is_drift():
    same = drift.compare(REFERENCE, _verdicts(30) + _verdicts(20, stage="stacked"))
    assert same["status"] == "stable" and same["max_psi"] < 0.01
    shifted = drift.compare(REFERENCE, _verdicts(50, score=0.97))  # newsletters scoring like phishing
    assert shifted["status"] == "drift" and shifted["psi"]["score"] > drift.PSI_LIMIT


def test_too_few_scans_or_a_stale_reference_publish_no_number():
    few = drift.compare(REFERENCE, _verdicts(drift.MIN_SCANS - 1))
    assert few["status"] == "not enough data" and "max_psi" not in few
    stale = drift.compare(REFERENCE, _verdicts(100), model_version="b2")
    assert stale["status"] == "stale reference" and "max_psi" not in stale


def test_the_bins_and_psi_behave():
    assert drift.score_bin(0.5) == 5 and drift.score_bin(1e-9) == 0 and drift.score_bin(1 - 1e-9) == 9
    assert drift.psi([10, 10], [10, 10]) == 0
    assert drift.psi([10, 0], [0, 10]) > 1  # an empty bin counts as a tiny share, so it stays finite


class FakeDynamo:
    def __init__(self, pages):
        self.pages, self.calls = pages, []

    def scan(self, **kwargs):
        self.calls.append(kwargs)
        return self.pages[len(self.calls) - 1]


class FakeCloudWatch:
    def __init__(self):
        self.metrics = None

    def put_metric_data(self, Namespace, MetricData):
        self.metrics = (Namespace, MetricData)


def test_the_weekly_run_reads_every_page_and_publishes_the_numbers(tmp_path, monkeypatch):
    (tmp_path / "bundle.json").write_text(json.dumps({"version": "b1"}))
    monkeypatch.setenv("PHISH_BUNDLE_DIR", str(tmp_path))
    reference = tmp_path / "reference.json"
    reference.write_text(json.dumps(REFERENCE))
    monkeypatch.setattr(drift, "REFERENCE", reference)
    item = lambda v: {"verdict": {"S": json.dumps(v)}}  # noqa: E731
    pages = [
        {"Items": [item(v) for v in _verdicts(20)], "LastEvaluatedKey": {"k": 1}},
        {"Items": [item(v) for v in _verdicts(20, stage="stacked") + _verdicts(5, version="old")]},
    ]
    db, cloudwatch = FakeDynamo(pages), FakeCloudWatch()
    result = drift.handler({}, None, db, cloudwatch)
    assert len(db.calls) == 2 and db.calls[1]["ExclusiveStartKey"] == {"k": 1}
    assert db.calls[0]["ProjectionExpression"] == "verdict"  # never more than the stored verdict
    assert result["scans"] == 40 and result["other_bundles"] == 5 and result["status"] == "stable"
    namespace, metrics = cloudwatch.metrics
    assert namespace == "phish-triage/drift" and {m["MetricName"] for m in metrics} == {"Scans", "MaxPSI"}
