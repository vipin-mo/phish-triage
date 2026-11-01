"""The cascade: each stage decides the emails it is sure about and passes the rest to the next, costlier stage.

A stage has two cutoffs on its probability of phishing, each the stricter of two limits:

- **confidence:** a stage only decides when it is sure, below `CONFIDENT_SAFE` or above `CONFIDENT_PHISH`;
- **validation error budget:** marking safe may let through at most `MAX_MISSED` of the validation phishing that
  reaches the stage, and flagging may hit at most `MAX_FALSE_ALARMS` of the validation legitimate mail.

The confidence limit matters when validation is too clean to show rare errors: on the `random` split the cheap
model separates validation perfectly, and the budgets alone would let it mark anything below 0.95 as safe, while
the test phishing it misses mostly scores between 0.5 and 0.95. In between the cutoffs, the email goes to the next
stage; the last stage decides everything it receives.

This answers "how much LLM do you actually need?" with measured shares, cost and latency, next to the single-model
rows (cheap model only, DistilBERT only, the LLM on everything).
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

MAX_MISSED = 0.001  # share of phishing a stage may wave through as safe
MAX_FALSE_ALARMS = 0.001  # share of legitimate mail a stage may flag on its own
CONFIDENT_SAFE, CONFIDENT_PHISH = 0.05, 0.95


@dataclass(frozen=True)
class Cutoffs:
    low: float  # score < low  -> safe
    high: float  # score > high -> phishing


def choose_cutoffs(
    y_val: np.ndarray,
    s_val: np.ndarray,
    max_missed: float = MAX_MISSED,
    max_false_alarms: float = MAX_FALSE_ALARMS,
    confident: tuple[float, float] = (CONFIDENT_SAFE, CONFIDENT_PHISH),
) -> Cutoffs:
    y_val, s_val = np.asarray(y_val), np.asarray(s_val, dtype=float)
    phish, legit = np.sort(s_val[y_val == 1]), np.sort(s_val[y_val == 0])[::-1]
    budget_low = phish[int(np.floor(max_missed * len(phish)))] if len(phish) else np.inf
    budget_high = legit[int(np.floor(max_false_alarms * len(legit)))] if len(legit) else -np.inf
    return Cutoffs(float(min(budget_low, confident[0])), float(max(budget_high, confident[1])))


def decide(scores: np.ndarray, cutoffs: Cutoffs) -> np.ndarray:
    """1 = phishing, 0 = safe, -1 = pass to the next stage.

    When validation separates the classes completely, `low` (the lowest phishing score) lies above `high` (the
    highest legitimate score). Validation says nothing about the gap between them, so emails there are passed on.
    """
    scores = np.asarray(scores, dtype=float)
    out = np.full(len(scores), -1)
    out[scores < min(cutoffs.low, cutoffs.high)] = 0
    out[scores > max(cutoffs.low, cutoffs.high)] = 1
    return out


@dataclass
class CascadeResult:
    decisions: np.ndarray  # final 0 / 1 per email
    stage: np.ndarray  # index of the stage that decided each email
    cutoffs: list[Cutoffs] = field(default_factory=list)

    def shares(self, n_stages: int) -> list[float]:
        return [float(np.mean(self.stage == k)) for k in range(n_stages)]


def run_cascade(
    val: list[tuple[np.ndarray, np.ndarray]],
    test_scores: list[np.ndarray],
    final_threshold: float,
) -> CascadeResult:
    """`val[k]` = (labels, scores) of stage k on the validation emails, for every stage but the last; the last
    stage decides with `final_threshold` (flag when score > threshold). `test_scores[k]` = stage k on test."""
    n = len(test_scores[0])
    decisions, stage = np.full(n, -1), np.full(n, -1)
    open_test = np.ones(n, dtype=bool)
    open_val = np.ones(len(val[0][0]), dtype=bool) if val else None
    cutoffs = []
    for k, (y_val, s_val) in enumerate(val):
        c = choose_cutoffs(y_val[open_val], s_val[open_val])
        cutoffs.append(c)
        d = decide(test_scores[k], c)
        settled = open_test & (d >= 0)
        decisions[settled], stage[settled] = d[settled], k
        open_test &= d < 0
        open_val &= decide(s_val, c) < 0
    last = len(test_scores) - 1
    decisions[open_test] = (np.asarray(test_scores[last])[open_test] > final_threshold).astype(int)
    stage[open_test] = last
    return CascadeResult(decisions, stage, cutoffs)
