import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "load_test_report", Path(__file__).parents[1] / "scripts" / "load_test_report.py"
)
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)


def point(metric, value, scenario, status=None, time="2026-11-04T18:38:03.27-06:00"):
    tags = {"scenario": scenario} | ({"status": status} if status else {})
    return json.dumps({"type": "Point", "metric": metric, "data": {"time": time, "value": value, "tags": tags}})


def test_stages_count_status_refusals_and_rate_over_the_stage(tmp_path):
    lines = [json.dumps({"type": "Metric", "metric": "http_req_duration", "data": {}})]
    lines += [point("http_req_duration", 70.0, "r1", "200") for _ in range(15)]
    lines += [point("http_req_duration", 130_000.0, "r1", "200", time="2026-11-04T18:40:13-06:00")]
    lines += [point("http_req_duration", 20.0, "r1", "429"), point("refused_by_gateway", 1, "r1")]
    lines += [point("http_req_duration", 40_000.0, "r1", "0")]
    path = tmp_path / "k6.jsonl"
    path.write_text("\n".join(lines) + "\n")

    s = report.summarize(report.k6_points(path))["r1"]
    assert s["requests"] == 18 and s["status"] == {"0": 1, "200": 16, "429": 1}
    assert s["refused_by_gateway"] == 1 and s["refused_by_key_limit"] == 0
    # 16 answered in a 30 s stage, however long one slow answer took to come back
    assert s["answered_per_second"] == round(16 / 30, 2)
    assert s["p50_ms"] == 70.0 and s["max_ms"] == 130_000.0


class FakeLogs:
    def __init__(self, pages):
        self.pages = pages

    def filter_log_events(self, nextToken=None, **kwargs):
        i = int(nextToken or 0)
        page = {"events": [{"timestamp": m.pop("_at_ms", 0), "message": json.dumps(m)} for m in self.pages[i]]}
        if i + 1 < len(self.pages):
            page["nextToken"] = str(i + 1)
        return page


def test_gateway_side_tells_the_refusals_apart_and_reads_every_page():
    entry = {"route": "ANY /{proxy+}", "error": "-", "_at_ms": 1_000}
    logs = FakeLogs(
        [
            [entry | {"status": "200", "integrationMs": "60", "latencyMs": "70"} for _ in range(3)],
            [
                entry | {"status": "429", "integrationMs": "-", "latencyMs": "1", "_at_ms": 2_500},
                entry | {"status": "429", "integrationMs": "30", "latencyMs": "35", "_at_ms": 38_000},
                entry | {"status": "200", "integrationMs": "150", "latencyMs": "164", "_at_ms": 170_000},
            ],
        ]
    )
    t = datetime(2026, 11, 5, tzinfo=UTC)
    g = report.gateway_side(t, t, logs)
    assert g["requests"] == 6
    assert g["status"] == {
        "200, function ran": 4,
        "429, function ran": 1,
        "429, refused before the function": 1,
    }
    assert g["ok_p50_ms"] == 70.0 and g["ok_max_ms"] == 164
    assert g["most_in_one_second"] == 3 and g["longest_pause_s"] == 132


def test_a_pause_longer_than_the_one_between_stages_marks_the_run_not_clean():
    lam = {"invocations": 0, "throttles": 0, "max_concurrent": 0, "cold_starts": 0, "model_load_s": []}
    gw = {"requests": 0, "status": {}, "most_in_one_second": 0, "ok_p50_ms": None, "ok_p95_ms": None, "ok_max_ms": None}
    clean = {"date": "2026-11-05", "stages": {}, "lambda": lam, "gateway": gw | {"longest_pause_s": 36}}
    assert not report.stalled(clean) and "Not a clean run" not in report.to_markdown(clean)
    stall = clean | {"gateway": gw | {"longest_pause_s": 131}}
    assert report.stalled(stall) and "no request for 131 s" in report.to_markdown(stall)


def test_settled_reads_until_two_reads_agree():
    reads = iter([{"invocations": 313}, {"invocations": 390}, {"invocations": 396}, {"invocations": 396}])
    waits = []
    assert report.settled(lambda: next(reads), sleep=waits.append) == {"invocations": 396}
    assert len(waits) == 3
