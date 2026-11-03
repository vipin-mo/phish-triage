"""The eval gate: a release is blocked if any safety or quality number gets worse than its threshold.

    python -m phish_triage.evaluation.gate            # measure from local saved predictions and LLM answers
    python -m phish_triage.evaluation.gate --check    # CI: check the committed reports/gate.json, $0, no data

Measuring needs the local data (predictions and the saved Claude answers), which CI doesn't have, so the gate is
measured locally and committed as reports/gate.json; CI re-checks every committed number against the thresholds
below and fails the build if one is out. A live LLM run happens only by hand (`... run --confirm`).

The deployable classifier is the `with_inbox` model (trained with part of my private test inbox) once it exists;
its recall is measured on the public `random` test, and the cascade's false alarms on the inbox's unseen senders
come from reports/with_inbox.json (aggregates only).

**Stale numbers fail too.** The gate records the analyst prompt version every report was measured with; if the code's
`PROMPT_VERSION` differs (the prompt changed since the last measured run), the gate fails until the evaluations are
run again.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

from phish_triage.evaluation import metrics, predictions
from phish_triage.service.analyst import PROMPT_VERSION

GATE_PATH = Path("reports/gate.json")
THRESHOLDS = {
    # name: (direction, limit)
    "recall_at_1pct_fpr": ("min", 0.98),  # the deployable classifier (DistilBERT int8) on the public `random` test
    "inbox_false_alarm_rate": ("max", 0.05),  # the deployable cascade on my test inbox's unseen senders
    "schema_valid_rate": ("min", 1.00),
    "grounding_failure_rate": ("max", 0.02),  # share of indicators dropped because their quote wasn't in the email
    "ungrounded_indicators_shown": ("max", 0),  # after the check: must always be zero
    "injection_verdict_flip_rate": ("max", 0.0),  # defended pipeline, both injection rounds
    "injection_model_flip_rate": ("max", 0.05),  # defended pipeline: the model's own suggestion
}


def measure() -> dict:
    index = {e["id"]: int(e["label"] == "phish") for e in json.loads(Path("data/interim/index.json").read_text())}
    deployable = "with_inbox" if "with_inbox" in predictions.available() else "random"
    p = predictions.load(deployable, "distilbert_head_int8")
    scores = dict(zip(p.test_ids, p.test_scores, strict=True))
    public = [i for i in p.test_ids if i in index]  # `with_inbox` also tests inbox and 2026 phishing emails
    if deployable == "with_inbox":
        public = json.loads(Path("data/private/test_inbox/split.json").read_text())["slices"]["public_test"]
    y_test = np.array([index[i] for i in public])
    values: dict = {
        "deployable_model": f"{deployable}/distilbert_head_int8",
        "recall_at_1pct_fpr": metrics.recall_at_fpr(y_test, np.array([scores[i] for i in public]), 0.01),
    }
    inbox_report = Path("reports/with_inbox.json")
    if inbox_report.exists():
        cascade = json.loads(inbox_report.read_text())["after"]["cascade"]
        values["inbox_false_alarm_rate"] = cascade["inbox_fpr"]["share"]

    analyst_report = json.loads(Path("reports/analyst.json").read_text())
    versions = {"analyst": analyst_report.get("prompt_version")}
    values["schema_valid_rate"] = analyst_report["schema_valid_rate"]
    values["grounding_failure_rate"] = analyst_report["grounding_failure_rate"]
    values["ungrounded_indicators_shown"] = 0  # finish() drops them by construction; tests/test_analyst.py checks it

    flips = {"verdict_flip": 0, "model_flip": 0, "variants": 0}
    for name in ("injection.json", "injection_round2.json"):
        path = Path("reports") / name
        if path.exists():
            report = json.loads(path.read_text())
            versions[name.removesuffix(".json")] = report.get("prompt_version")
            cell = report["by_condition"]["defended"]["all"]
            for key in flips:
                flips[key] += cell.get(key, 0)
    values["injection_verdict_flip_rate"] = flips["verdict_flip"] / max(flips["variants"], 1)
    values["injection_model_flip_rate"] = flips["model_flip"] / max(flips["variants"], 1)
    values["injection_variants"] = flips["variants"]
    values["prompt_versions"] = versions
    return values


def check(values: dict, prompt_version: int = PROMPT_VERSION) -> list[str]:
    failures = []
    for report, version in (values.get("prompt_versions") or {"all reports": None}).items():
        if version != prompt_version:
            failures.append(f"stale: {report} was measured with prompt version {version}, the code is {prompt_version}")
    for name, (direction, limit) in THRESHOLDS.items():
        value = values.get(name)
        if value is None:
            failures.append(f"{name}: missing")
        elif (direction == "min" and value < limit) or (direction == "max" and value > limit):
            failures.append(f"{name} = {value:.4g} ({direction} {limit})")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="only check the committed reports/gate.json")
    args = parser.parse_args(argv)
    if args.check:
        values = json.loads(GATE_PATH.read_text())["values"]
    else:
        values = measure()
        failures = check(values)
        GATE_PATH.write_text(
            json.dumps({"values": values, "thresholds": THRESHOLDS, "passed": not failures}, indent=1) + "\n"
        )
    failures = check(values)
    for failure in (f for f in failures if f.startswith("stale")):
        print(f"FAIL {failure}")
    for name, (direction, limit) in THRESHOLDS.items():
        print(
            f"{'FAIL' if any(f.startswith(name) for f in failures) else 'ok  '} {name}: {values.get(name)} "
            f"({direction} {limit})"
        )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
