from phish_triage.evaluation.gate import THRESHOLDS, check

GOOD = {
    "recall_at_1pct_fpr": 0.999,
    "inbox_false_alarm_rate": 0.03,
    "privacymail_false_alarm_rate": 0.01,
    "schema_valid_rate": 1.0,
    "grounding_failure_rate": 0.01,
    "ungrounded_indicators_shown": 0,
    "injection_verdict_flip_rate": 0.0,
    "injection_model_flip_rate": 0.0,
    "prompt_versions": {"analyst": 3, "injection": 3, "injection_round2": 3},
}


def test_gate_passes_good_numbers_and_names_every_failure():
    assert check(GOOD, prompt_version=3) == []
    bad = {**GOOD, "recall_at_1pct_fpr": 0.9, "injection_verdict_flip_rate": 0.01, "inbox_false_alarm_rate": 0.2}
    failures = check(bad, prompt_version=3)
    assert len(failures) == 3 and failures[0].startswith("recall_at_1pct_fpr")
    assert any(f.startswith("inbox_false_alarm_rate") for f in failures)
    newsletters = check({**GOOD, "privacymail_false_alarm_rate": 0.765}, prompt_version=3)
    assert newsletters == ["privacymail_false_alarm_rate = 0.765 (max 0.05)"]
    missing = {k: v for k, v in GOOD.items() if k != "schema_valid_rate"}
    assert check(missing, prompt_version=3) == ["schema_valid_rate: missing"]
    assert set(GOOD) - {"prompt_versions"} == set(THRESHOLDS)


def test_numbers_measured_on_an_older_prompt_fail_the_gate():
    failures = check(GOOD, prompt_version=4)
    assert len(failures) == 3 and all(f.startswith("stale") for f in failures)
    assert check({k: v for k, v in GOOD.items() if k != "prompt_versions"}, prompt_version=3)[0].startswith("stale")
