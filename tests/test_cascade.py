import numpy as np

from phish_triage.evaluation.cascade import Cutoffs, choose_cutoffs, decide, run_cascade


def test_cutoffs_respect_the_error_budgets():
    y = np.array([1] * 1000 + [0] * 1000)
    s = np.concatenate([np.linspace(0.3, 1.0, 1000), np.linspace(0.0, 0.7, 1000)])
    c = choose_cutoffs(y, s, max_missed=0.01, max_false_alarms=0.01, confident=(1.0, 0.0))  # budgets only
    assert np.mean(s[y == 1] < c.low) <= 0.01 and np.mean(s[y == 0] > c.high) <= 0.01
    assert list(decide(np.array([0.1, 0.5, 0.95]), c)) == [0, -1, 1]


def test_a_stage_only_decides_where_it_is_confident():
    # Validation is perfectly separated, so the budgets alone would decide everything below 0.6 / above 0.4.
    y = np.array([1] * 100 + [0] * 100)
    s = np.concatenate([np.linspace(0.6, 1, 100), np.linspace(0, 0.4, 100)])
    c = choose_cutoffs(y, s)
    assert (c.low, c.high) == (0.05, 0.95)
    assert list(decide(np.array([0.01, 0.3, 0.8, 0.99]), c)) == [0, -1, -1, 1]


def test_cascade_passes_only_uncertain_emails_on():
    # Stage 0 is sure about the extremes; stage 1 (the last) gets the middle and decides it.
    y_val = np.array([1] * 100 + [0] * 100)
    s0_val = np.concatenate([np.linspace(0.6, 1, 100), np.linspace(0, 0.4, 100)])
    test0 = np.array([0.01, 0.99, 0.5, 0.45])  # 0.5 and 0.45 fall in the gap between the classes
    test1 = np.array([0.0, 0.0, 0.9, 0.1])
    result = run_cascade([(y_val, s0_val)], [test0, test1], final_threshold=0.5)
    assert list(result.decisions) == [0, 1, 1, 0]
    assert list(result.stage) == [0, 0, 1, 1]
    assert result.shares(2) == [0.5, 0.5]


def test_the_gap_between_separated_classes_is_passed_on():
    assert list(decide(np.array([0.3, 0.5, 0.7]), Cutoffs(low=0.6, high=0.4))) == [0, -1, 1]
