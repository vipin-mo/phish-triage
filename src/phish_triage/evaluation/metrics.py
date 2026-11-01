"""The metrics every model in this project is reported with.

Accuracy on a 50/50 test set says little about a mail filter: real inboxes are mostly legitimate, and every false
alarm costs someone's attention. So the headline numbers are:

- **recall at a fixed false-alarm rate** (1% and 0.1% of legitimate mail flagged), read off the test ROC curve;
- **the operating point:** a threshold chosen on the validation split for a 1% false-alarm rate, then applied to
  the test split, which shows the false-alarm rate a deployed model would really have;
- **precision at a realistic phishing rate** (1 in 100 emails by default), computed from that operating point's
  recall and false-alarm rate, because precision on a 50/50 sample is inflated by the sample, not the model;
- **PR-AUC**, and **expected calibration error** with a reliability curve for models that output probabilities;
- **95% bootstrap intervals** for every number. Resampling is done within each class, so every resample has the
  same number of phishing and legitimate emails as the test set.

`scores` are "higher means more likely phishing"; labels are 1 for phishing and 0 for legitimate.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass

import numpy as np
from sklearn.metrics import average_precision_score

PREVALENCE = 0.01  # 1 phishing email in 100
FPR_TARGETS = (0.01, 0.001)
N_BOOTSTRAP = 1000
CALIBRATION_BINS = 15


@dataclass(frozen=True)
class Estimate:
    value: float
    low: float
    high: float

    def __str__(self) -> str:
        return f"{self.value:.3f} [{self.low:.3f}, {self.high:.3f}]"


def recall_at_fpr(y: np.ndarray, scores: np.ndarray, fpr: float) -> float:
    """Highest recall reachable while flagging at most `fpr` of the legitimate emails (ties count against it).

    With n legitimate emails, floor(fpr * n) false alarms are allowed; with fewer than 1/fpr legitimate emails
    that means none at all, so 0.1% needs at least 1,000 legitimate test emails to mean what it says.
    """
    y, scores = np.asarray(y), np.asarray(scores, dtype=float)
    negatives = np.sort(scores[y == 0])[::-1]
    allowed = int(np.floor(fpr * len(negatives) + 1e-9))
    # Everything strictly above the (allowed + 1)-th highest legitimate score can be flagged.
    threshold = negatives[allowed] if allowed < len(negatives) else -np.inf
    return float(np.mean(scores[y == 1] > threshold))


def threshold_at_fpr(y: np.ndarray, scores: np.ndarray, fpr: float) -> float:
    """The lowest threshold (flag when score > threshold) that keeps the false-alarm rate at or below `fpr`."""
    negatives = np.sort(np.asarray(scores, dtype=float)[np.asarray(y) == 0])[::-1]
    allowed = int(np.floor(fpr * len(negatives) + 1e-9))
    return float(negatives[allowed]) if allowed < len(negatives) else float("-inf")


def rates_at_threshold(y: np.ndarray, scores: np.ndarray, threshold: float) -> tuple[float, float]:
    """(recall, false-alarm rate) when flagging every email with score > threshold."""
    y, flagged = np.asarray(y), np.asarray(scores, dtype=float) > threshold
    return float(flagged[y == 1].mean()), float(flagged[y == 0].mean())


def precision_at_prevalence(recall: float, fpr: float, prevalence: float = PREVALENCE) -> float:
    """Precision if phishing made up `prevalence` of all mail, at the given recall and false-alarm rate."""
    flagged = recall * prevalence + fpr * (1 - prevalence)
    return float(recall * prevalence / flagged) if flagged else float("nan")


def pr_auc(y: np.ndarray, scores: np.ndarray) -> float:
    return float(average_precision_score(y, scores))


def expected_calibration_error(y: np.ndarray, probs: np.ndarray, bins: int = CALIBRATION_BINS) -> float:
    """Average gap between predicted probability and observed phishing rate, over equal-width bins."""
    curve = reliability_curve(y, probs, bins)
    total = sum(row["count"] for row in curve)
    return float(sum(row["count"] * abs(row["mean_predicted"] - row["observed"]) for row in curve) / total)


def reliability_curve(y: np.ndarray, probs: np.ndarray, bins: int = CALIBRATION_BINS) -> list[dict]:
    y, probs = np.asarray(y), np.clip(np.asarray(probs, dtype=float), 0, 1)
    index = np.minimum((probs * bins).astype(int), bins - 1)
    curve = []
    for b in range(bins):
        members = index == b
        if members.any():
            curve.append(
                {
                    "bin": [b / bins, (b + 1) / bins],
                    "count": int(members.sum()),
                    "mean_predicted": float(probs[members].mean()),
                    "observed": float(y[members].mean()),
                }
            )
    return curve


def bootstrap(
    metric: Callable[[np.ndarray, np.ndarray], float],
    y: np.ndarray,
    scores: np.ndarray,
    n: int = N_BOOTSTRAP,
    seed: int = 0,
) -> Estimate:
    """The metric on the full sample, with a 95% interval from a class-stratified bootstrap."""
    y, scores = np.asarray(y), np.asarray(scores, dtype=float)
    rng = np.random.default_rng(seed)
    pos, neg = np.flatnonzero(y == 1), np.flatnonzero(y == 0)
    values = []
    for _ in range(n):
        sample = np.concatenate([rng.choice(pos, len(pos)), rng.choice(neg, len(neg))])
        values.append(metric(y[sample], scores[sample]))
    low, high = np.nanpercentile(values, [2.5, 97.5])
    return Estimate(metric(y, scores), float(low), float(high))


@dataclass(frozen=True)
class Report:
    n_phish: int
    n_legit: int
    pr_auc: Estimate
    recall_at_fpr: dict[str, Estimate]  # "1%" / "0.1%" -> recall read off the test ROC curve
    threshold: float  # chosen on validation for a 1% false-alarm rate
    test_recall: Estimate  # at that threshold, on test
    test_fpr: Estimate
    precision_at_prevalence: Estimate  # at that threshold, if 1 in 100 emails were phishing
    ece: Estimate | None  # only for models that output probabilities

    def to_dict(self) -> dict:
        return asdict(self)


def evaluate(
    y_test: np.ndarray,
    test_scores: np.ndarray,
    *,
    threshold: float,
    probabilities: bool,
    prevalence: float = PREVALENCE,
    n_bootstrap: int = N_BOOTSTRAP,
    seed: int = 0,
) -> Report:
    """Every headline metric for one model on one test set. `threshold` comes from `threshold_at_fpr` on val."""
    y_test, test_scores = np.asarray(y_test), np.asarray(test_scores, dtype=float)

    def boot(metric):
        return bootstrap(metric, y_test, test_scores, n_bootstrap, seed)

    def precision(y, s):
        return precision_at_prevalence(*rates_at_threshold(y, s, threshold), prevalence)

    return Report(
        n_phish=int((y_test == 1).sum()),
        n_legit=int((y_test == 0).sum()),
        pr_auc=boot(pr_auc),
        recall_at_fpr={f"{fpr:.1%}".replace(".0%", "%"): boot(_recall_at(fpr)) for fpr in FPR_TARGETS},
        threshold=threshold,
        test_recall=boot(lambda y, s: rates_at_threshold(y, s, threshold)[0]),
        test_fpr=boot(lambda y, s: rates_at_threshold(y, s, threshold)[1]),
        precision_at_prevalence=boot(precision),
        ece=boot(expected_calibration_error) if probabilities else None,
    )


def _recall_at(fpr: float) -> Callable[[np.ndarray, np.ndarray], float]:
    return lambda y, s: recall_at_fpr(y, s, fpr)
