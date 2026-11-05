"""Summarize a load-test run (reports/load_test.md); `make load-test` runs k6 and then this.

    python scripts/load_test_report.py build/loadtest.jsonl    # needs the MFA session for the Lambda side

From k6's per-request output: per stage, the requests, their status codes, the scans per second that got through,
and the latency of the ones that did (p50, p95, max), as my laptop saw them. From AWS for the same minutes: API
Gateway's access log (each request's status, whether the function ran, and the gateway's own latency, so a stall on
my side shows up as a gap between the two), and the scan function's invocations, throttles and most concurrent copies,
and how many copies loaded the model (cold starts) and how long that took. Lambda's metrics arrive a few minutes late,
so they are read again until they stop changing. If the gateway saw a longer pause than the one between stages (my
laptop slept or lost the network), the report says the run is not clean and this exits 1. Only numbers; the
requests are a hand-made newsletter.
"""

from __future__ import annotations

import json
import sys
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np

REPORT = Path("reports/load_test")
STAGES = {
    "r1": "1 a second, 30 s",
    "r2": "2 a second, 30 s",
    "r5": "5 a second, 30 s",
    "r10": "10 a second, 30 s",
}
STAGE_SECONDS = 30  # loadtest/scan.js
PAUSE_SECONDS = 35  # between stages in loadtest/scan.js; a longer quiet spell at the gateway is a stall on my side


def k6_points(path: Path) -> dict:
    """Per stage: durations of the answered requests, status counts, and the first and last time."""
    stages: dict = defaultdict(lambda: {"ms": [], "ok_ms": [], "status": Counter(), "times": [], "refused": Counter()})
    for line in path.read_text().splitlines():
        point = json.loads(line)
        if point.get("type") != "Point":
            continue
        if point.get("metric") in ("refused_by_gateway", "refused_by_key_limit"):
            stages[point["data"]["tags"].get("scenario", "?")]["refused"][point["metric"]] += 1
            continue
        if point.get("metric") != "http_req_duration":
            continue
        tags, data = point["data"]["tags"], point["data"]
        stage = stages[tags.get("scenario", "?")]
        stage["status"][tags.get("status", "?")] += 1
        stage["ms"].append(data["value"])
        if tags.get("status") == "200":
            stage["ok_ms"].append(data["value"])
        stage["times"].append(datetime.fromisoformat(data["time"]))
    return stages


def summarize(stages: dict) -> dict:
    out = {}
    for name in STAGES:
        if name not in stages:
            continue
        s = stages[name]
        ok = np.array(s["ok_ms"])
        out[name] = {
            "requests": len(s["ms"]),
            "status": dict(sorted(s["status"].items())),
            "answered_per_second": round(len(ok) / STAGE_SECONDS, 2),
            "p50_ms": round(float(np.percentile(ok, 50)), 1) if len(ok) else None,
            "p95_ms": round(float(np.percentile(ok, 95)), 1) if len(ok) else None,
            "max_ms": round(float(ok.max()), 1) if len(ok) else None,
            "refused_by_gateway": s["refused"]["refused_by_gateway"],
            "refused_by_key_limit": s["refused"]["refused_by_key_limit"],
        }
    return out


def gateway_side(start: datetime, end: datetime, logs) -> dict:
    """API Gateway's access log: status codes, which requests reached the function, and the gateway's latency."""
    status, latency, seconds = Counter(), [], []
    for at_ms, entry in log_entries(logs, "/aws/apigateway/phish-triage", start, end):
        seconds.append(at_ms // 1000)
        ran = entry.get("integrationMs", "-") != "-"
        status[f"{entry['status']}, {'function ran' if ran else 'refused before the function'}"] += 1
        if entry["status"] == "200":
            latency.append(int(entry["latencyMs"]))
    ok, seconds = np.array(latency), sorted(seconds)
    return {
        "requests": sum(status.values()),
        "longest_pause_s": int(np.diff(seconds).max()) if len(seconds) > 1 else 0,
        "most_in_one_second": max(Counter(seconds).values(), default=0),
        "status": dict(sorted(status.items())),
        "ok_p50_ms": round(float(np.percentile(ok, 50)), 1) if len(ok) else None,
        "ok_p95_ms": round(float(np.percentile(ok, 95)), 1) if len(ok) else None,
        "ok_max_ms": int(ok.max()) if len(ok) else None,
    }


def log_entries(logs, group: str, start: datetime, end: datetime, pattern: str = ""):
    token = None
    while True:
        kwargs = {
            "logGroupName": group,
            "startTime": int(start.timestamp() * 1000),
            "endTime": int(end.timestamp() * 1000),
            "filterPattern": pattern,
        }
        if token:
            kwargs["nextToken"] = token
        page = logs.filter_log_events(**kwargs)
        for event in page.get("events", []):
            yield event["timestamp"], json.loads(event["message"][event["message"].index("{") :])
        if not (token := page.get("nextToken")):
            return


def settled(read, wait_s: int = 60, tries: int = 10, sleep=time.sleep) -> dict:
    """Read again every `wait_s` until two reads agree (Lambda's metrics come in late), at most `tries` times."""
    last = read()
    for _ in range(tries):
        sleep(wait_s)
        if (now := read()) == last:
            return now
        last = now
    return last


def lambda_side(start: datetime, end: datetime, cloudwatch, logs) -> dict:
    def stat(metric: str, statistic: str) -> float:
        points = cloudwatch.get_metric_statistics(
            Namespace="AWS/Lambda",
            MetricName=metric,
            Dimensions=[{"Name": "FunctionName", "Value": "phish-triage-scan"}],
            StartTime=start,
            EndTime=end,
            Period=60,
            Statistics=[statistic],
        )["Datapoints"]
        values = [p[statistic] for p in points]
        return (max(values) if statistic == "Maximum" else sum(values)) if values else 0.0

    loads = [
        sum(v for k, v in entry.items() if k.endswith("_ms"))
        for _, entry in log_entries(logs, "/aws/lambda/phish-triage-scan", start, end, '"scanner_loaded"')
    ]
    return {
        "invocations": int(stat("Invocations", "Sum")),
        "throttles": int(stat("Throttles", "Sum")),
        "max_concurrent": int(stat("ConcurrentExecutions", "Maximum")),
        "cold_starts": len(loads),
        "model_load_s": [round(ms / 1000, 1) for ms in sorted(loads)],
    }


def stalled(r: dict) -> bool:
    return r["gateway"]["longest_pause_s"] > PAUSE_SECONDS + 5


def to_markdown(r: dict) -> str:
    lam, gw = r["lambda"], r["gateway"]
    rows = [
        f"| {name} ({STAGES[name]}) | {s['requests']} | "
        + ", ".join(f"{code}: {n}" for code, n in s["status"].items())
        + f" | {s['refused_by_gateway']} | {s['refused_by_key_limit']} | {s['answered_per_second']} | {s['p50_ms']} | "
        f"{s['p95_ms']} | {s['max_ms']} |"
        for name, s in r["stages"].items()
    ]
    return "\n".join(
        [
            "# Load test of the live API",
            "",
            f"Generated by `make load-test` on {r['date']} (k6, `loadtest/scan.js`). Every request is the same "
            "hand-made newsletter with a unique header, so each is a new scan; its own API key, left out of the "
            "real-use report. The limits in front of the function: API Gateway 5 requests a second (bursts of 10), "
            "60 a minute per key, at most 5 copies of the function at once.",
            "",
            *(
                [
                    f"**Not a clean run:** API Gateway saw no request for {r['gateway']['longest_pause_s']} s, longer "
                    f"than the {PAUSE_SECONDS} s between stages, so my laptop or its network stopped during it.",
                    "",
                ]
                if stalled(r)
                else []
            ),
            "| Stage | Requests | Status codes | 429 by API Gateway | 429 by key limit | Answered per second "
            "| p50 ms | p95 ms | max ms |",
            "|---|---:|---|---:|---:|---:|---:|---:|---:|",
            *rows,
            "",
            "Latencies are of the answered (200) scans, end to end from my laptop; status 0 is a request my laptop "
            "gave up on (40 s). A 503 is API Gateway's answer when the function's concurrency cap throttles a request. "
            "Answered per second is over the stage's 30 s. The key limit counts per calendar minute, so a stage that "
            "spans two minutes can get up to 120 answers.",
            "",
            "| API Gateway's access log, same minutes | |",
            "|---|---:|",
            f"| Requests | {gw['requests']} |",
            f"| Longest pause between requests, s (the stages are {PAUSE_SECONDS} s apart) | {gw['longest_pause_s']} |",
            f"| Most requests in one second | {gw['most_in_one_second']} |",
            *[f"| {k} | {n} |" for k, n in gw["status"].items()],
            f"| Answered (200): p50 / p95 / max ms at the gateway | {gw['ok_p50_ms']} / {gw['ok_p95_ms']} / "
            f"{gw['ok_max_ms']} |",
            "",
            "| The scan function, same minutes | |",
            "|---|---:|",
            f"| Invocations | {lam['invocations']} |",
            f"| Throttled by the concurrency cap | {lam['throttles']} |",
            f"| Most copies at once | {lam['max_concurrent']} |",
            f"| Copies that loaded the model (cold starts) | {lam['cold_starts']} |",
            f"| Model load, seconds | {', '.join(map(str, lam['model_load_s'])) or '—'} |",
            "",
        ]
    )


def main(argv: list[str]) -> int:
    import boto3

    stages = k6_points(Path(argv[0]))
    times = [t for s in stages.values() for t in s["times"]]
    start, end = min(times) - timedelta(minutes=1), max(times) + timedelta(minutes=2)
    cloudwatch, logs = boto3.client("cloudwatch"), boto3.client("logs")
    result = {
        "date": min(times).astimezone(UTC).strftime("%Y-%m-%d"),
        "stages": summarize(stages),
        "gateway": settled(lambda: gateway_side(start, end, logs)),
        "lambda": settled(lambda: lambda_side(start, end, cloudwatch, logs)),
    }
    REPORT.with_suffix(".json").write_text(json.dumps(result, indent=1) + "\n")
    REPORT.with_suffix(".md").write_text(to_markdown(result))
    print(to_markdown(result))
    return 1 if stalled(result) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
