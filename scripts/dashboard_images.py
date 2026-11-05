"""The service's CloudWatch dashboard as images for the README (docs/dashboard/); `make dashboard-images`.

    python scripts/dashboard_images.py 2026-11-04T00:00:00Z 2026-11-05T18:00:00Z   # needs the MFA session

Each panel of the `phish-triage` dashboard is rendered by CloudWatch's own API (`GetMetricWidgetImage`), not a
screenshot of the console, so no account ID, address or console page is in the picture. Every series gets a plain
label, so the API's ID, which is part of its URL, isn't printed in a legend either.
"""

from __future__ import annotations

import base64
import copy
import json
import sys
from pathlib import Path

OUT = Path("docs/dashboard")
PANELS = {  # dashboard order -> (file name, a label for each series)
    0: ("scans_and_errors", ["Scans", "Errors", "Throttles"]),
    1: ("scan_time", ["Scan time, average", "Scan time, p95"]),
    2: ("api_status", ["Requests", "4xx", "5xx"]),
    3: ("api_latency", ["Latency, p95"]),
}


def widget(properties: dict, labels: list[str], start: str, end: str) -> dict:
    p = copy.deepcopy(properties)
    metrics = []
    for metric, label in zip(p["metrics"], labels, strict=True):
        metric = list(metric)
        options = metric.pop() if metric and isinstance(metric[-1], dict) else {}
        metrics.append([*metric, {**options, "label": label}])
    return p | {"metrics": metrics, "width": 900, "height": 320, "start": start, "end": end, "timezone": "+0000"}


def main(argv: list[str]) -> int:
    import boto3

    start, end = argv[0], argv[1]
    cloudwatch = boto3.client("cloudwatch", region_name="us-east-2")
    body = json.loads(cloudwatch.get_dashboard(DashboardName="phish-triage")["DashboardBody"])
    OUT.mkdir(parents=True, exist_ok=True)
    for index, (name, labels) in PANELS.items():
        spec = widget(body["widgets"][index]["properties"], labels, start, end)
        image = cloudwatch.get_metric_widget_image(MetricWidget=json.dumps(spec))["MetricWidgetImage"]
        (OUT / f"{name}.png").write_bytes(image if isinstance(image, bytes) else base64.b64decode(image))
        print(f"{OUT / name}.png", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
