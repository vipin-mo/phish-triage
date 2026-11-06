from phish_triage.evaluation.gate import THRESHOLDS, check

REPORTS = ("analyst", "injection", "injection_round2")
BUNDLE = "with-newsletters-20261104-abcdef12"
GOOD = {
    "recall_at_1pct_fpr": 0.999,
    "inbox_false_alarm_rate": 0.03,
    "privacymail_false_alarm_rate": 0.01,
    "schema_valid_rate": 1.0,
    "grounding_failure_rate": 0.01,
    "injection_verdict_flip_rate": 0.0,
    "injection_model_flip_rate": 0.0,
    "injection_variants": 360,
    "prompt_versions": dict.fromkeys(REPORTS, 3),
    "llm_models": dict.fromkeys(REPORTS, "claude-test"),
    "llm_classifiers": dict.fromkeys(REPORTS, BUNDLE),
    "deployable_model": "with_newsletters/distilbert_head",
}
KEYS = {"prompt_versions", "llm_models", "llm_classifiers", "deployable_model"}


def run(values: dict, prompt_version: int = 3, bundle: str = BUNDLE) -> list[str]:
    return check(
        values, prompt_version=prompt_version, llm_model="claude-test", bundle_version=bundle, drift_bundle=BUNDLE
    )


def test_gate_passes_good_numbers_and_names_every_failure():
    assert run(GOOD) == []
    bad = {**GOOD, "recall_at_1pct_fpr": 0.9, "injection_verdict_flip_rate": 0.01, "inbox_false_alarm_rate": 0.2}
    failures = run(bad)
    assert len(failures) == 3 and failures[0].startswith("recall_at_1pct_fpr")
    assert any(f.startswith("inbox_false_alarm_rate") for f in failures)
    newsletters = run({**GOOD, "privacymail_false_alarm_rate": 0.765})
    assert newsletters == ["privacymail_false_alarm_rate = 0.765 (max 0.05)"]
    missing = {k: v for k, v in GOOD.items() if k != "schema_valid_rate"}
    assert run(missing) == ["schema_valid_rate: missing"]
    assert set(GOOD) - KEYS == set(THRESHOLDS)


def test_numbers_measured_on_an_older_prompt_fail_the_gate():
    failures = run(GOOD, prompt_version=4)
    assert len(failures) == 3 and all(f.startswith("stale") for f in failures)
    assert run({k: v for k, v in GOOD.items() if k != "prompt_versions"})[0].startswith("stale")


def test_another_claude_model_or_bundle_fails_the_gate():
    other_model = check(GOOD, prompt_version=3, llm_model="claude-other", bundle_version=BUNDLE, drift_bundle=BUNDLE)
    assert other_model[0].startswith("stale")
    old_reference = check(GOOD, prompt_version=3, llm_model="claude-test", bundle_version=BUNDLE, drift_bundle="old")
    assert old_reference == [f"stale: the drift reference is for old, the deployed bundle is {BUNDLE}"]
    behind_old = {**GOOD, "llm_classifiers": {**GOOD["llm_classifiers"], "injection": "with-inbox-20261104-1"}}
    assert len(run(behind_old)) == 1
    assert any("not a bundle of a deployable split" in f for f in run(GOOD, bundle="random-20261104-ab12cd34"))


def test_a_missing_injection_round_or_a_nan_fails_instead_of_passing():
    one_round = {**GOOD, "injection_variants": 240, "prompt_versions": {**GOOD["prompt_versions"], "injection": None}}
    failures = run(one_round)
    assert any(f.startswith("injection_variants") for f in failures) and any("stale" in f for f in failures)
    assert run({**GOOD, "grounding_failure_rate": float("nan")}) == ["grounding_failure_rate = nan (max 0.02)"]


def test_recall_measured_for_another_model_fails():
    assert any(
        "recall was measured for random/distilbert_head" in f
        for f in run(GOOD | {"deployable_model": "random/distilbert_head"})
    )
    assert run(GOOD | {"injection_verdict_drop_rate": 0.01}) == []  # reported, no limit yet (see REPORTED in gate.py)


def test_a_retrained_bundle_is_checked_against_the_distilbert_it_runs():
    # `with_retraining` refits stage 1 only and runs the newsletters split's DistilBERT (bundle.DISTILBERT_FROM)
    retrained = "with-retraining-20261201-abcdef12"
    values = GOOD | {"llm_classifiers": dict.fromkeys(REPORTS, retrained)}
    kwargs = {"prompt_version": 3, "llm_model": "claude-test", "bundle_version": retrained, "drift_bundle": retrained}
    assert check(values, **kwargs) == []
