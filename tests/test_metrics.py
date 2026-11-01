import numpy as np
import pytest

from phish_triage.evaluation import metrics

# 1,000 legitimate emails scored 0..999 / 1000, and 10 phishing emails between them.
LEGIT = np.arange(1000) / 1000
PHISH = np.array([0.9995, 0.9985, 0.9975, 0.9965, 0.9955, 0.9945, 0.9935, 0.9925, 0.9905, 0.5])
Y = np.concatenate([np.zeros(1000, int), np.ones(10, int)])
S = np.concatenate([LEGIT, PHISH])


def test_recall_at_fpr_counts_allowed_false_alarms():
    # 1% of 1,000 legitimate = 10 false alarms allowed: flag everything above the 11th-highest legit score (0.989).
    assert metrics.recall_at_fpr(Y, S, 0.01) == 0.9
    # 0.1% = 1 false alarm: flag above 0.998, which catches the top two phishing emails.
    assert metrics.recall_at_fpr(Y, S, 0.001) == 0.2


def test_recall_at_fpr_with_too_few_negatives_allows_none():
    y = np.array([0, 0, 1])
    assert metrics.recall_at_fpr(y, np.array([0.1, 0.9, 0.5]), 0.001) == 0.0
    assert metrics.recall_at_fpr(y, np.array([0.1, 0.4, 0.5]), 0.001) == 1.0


def test_threshold_from_validation_is_applied_unchanged():
    threshold = metrics.threshold_at_fpr(Y, S, 0.01)
    recall, fpr = metrics.rates_at_threshold(Y, S, threshold)
    assert (recall, fpr) == (0.9, 0.01)
    recall, fpr = metrics.rates_at_threshold(Y, S - 0.5, threshold)  # a shifted "test" set
    assert recall == 0.0 and fpr == 0.0


def test_precision_at_prevalence():
    # A perfect-recall model flagging 1% of legitimate mail, when 1% of mail is phishing: half the flags are wrong.
    assert metrics.precision_at_prevalence(1.0, 0.01, 0.01) == pytest.approx(1 / 1.99)
    assert metrics.precision_at_prevalence(0.9, 0.0, 0.01) == 1.0
    assert np.isnan(metrics.precision_at_prevalence(0.0, 0.0))


def test_calibration_error():
    y = np.array([0, 0, 1, 1])
    assert metrics.expected_calibration_error(y, np.array([0.0, 0.0, 1.0, 1.0])) == 0.0
    assert metrics.expected_calibration_error(y, np.full(4, 0.5)) == pytest.approx(0.0)  # 0.5 predicted, 0.5 seen
    assert metrics.expected_calibration_error(y, np.array([1.0, 1.0, 0.0, 0.0])) == pytest.approx(1.0)


def test_bootstrap_interval_contains_the_value_and_keeps_class_counts():
    seen = []

    def metric(y, s):
        seen.append(int(y.sum()))
        return metrics.recall_at_fpr(y, s, 0.01)

    estimate = metrics.bootstrap(metric, Y, S, n=200, seed=1)
    assert estimate.low <= estimate.value <= estimate.high
    assert set(seen) == {10}


def test_evaluate_reports_everything():
    threshold = metrics.threshold_at_fpr(Y, S, 0.01)
    report = metrics.evaluate(Y, S, threshold=threshold, probabilities=True, n_bootstrap=50)
    assert (report.n_phish, report.n_legit) == (10, 1000)
    assert set(report.recall_at_fpr) == {"1%", "0.1%"}
    assert report.recall_at_fpr["1%"].value == 0.9
    assert report.test_fpr.value == 0.01
    assert report.ece is not None
    assert metrics.evaluate(Y, S, threshold=threshold, probabilities=False, n_bootstrap=5).ece is None
