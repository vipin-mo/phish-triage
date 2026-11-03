"""The baseline models: cheap, explainable, and the first stage of the cascade later.

- `course`: my course project's setup (word TF-IDF, 10k features, logistic regression), kept as a reference row.
- `text`: TF-IDF on words (1-2 grams) and characters (3-5 grams) + logistic regression. Character n-grams catch
  obfuscated words ("p@ssword", "verlfy") and survive the odd spellings phishing uses.
- `features`: gradient-boosted trees on the structured signals only (`features/extract.py`).
- `stacked`: the same trees on the structured signals plus the text model's score. On the training split the
  text score is out-of-fold (5-fold), so the trees never see a score the text model produced on its own
  training data. The TF-IDF vocabulary is fitted once on the whole training split (it uses no labels); only the
  logistic regression is refitted per fold.
- Calibrated versions (isotonic regression) are fitted on the validation split only.

Every text model, DistilBERT included, reads `email_text`: the subject and the body a reader sees. With HTML that is
the visible HTML text (hidden elements removed), because mail programs show the HTML part: a harmless plain-text
part next to phishing HTML, or hidden filler, would otherwise decide what the model reads. When the HTML shows
almost no words (an image-only email), the plain-text part is used. The source's names are masked in it as in the
plain text, URLs and addresses included (`data/mask.py` keeps them in the HTML for the link features). Years, month
and weekday names are removed, because the private test inbox is all late 2026 and the text models learned dates as
a sign of legitimate mail.

scikit-learn's HistGradientBoostingClassifier is used instead of LightGBM: the same histogram-based algorithm,
with native missing-value handling, and no extra native library to ship to Lambda.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.frozen import FrozenEstimator
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.pipeline import FunctionTransformer, Pipeline, make_union

from phish_triage.data.mask import mask_source_names
from phish_triage.features.html import visible_html

TEXT_CHARS = 20_000  # words: the first 20k characters of the body
CHAR_NGRAM_CHARS = 3_000  # character n-grams: the first 3k (enough, and much faster)
SEED = 20261029


MIN_VISIBLE_WORDS = 5  # fewer visible HTML words than this: read the plain-text part instead
_MONTH_OR_DAY = r"jan|feb|mar|apr|may|jun|jul|aug|sept?|oct|nov|dec|mon|tue|wed|thu|fri|sat|sun"
# Years; full month and weekday names (except "May", a common word); and abbreviations next to a number ("3 Nov",
# "Mon, 3", "Wed, Oct 7", "May 2026"). No nested repeats, so crafted input can't make it backtrack.
DATE_WORDS = re.compile(
    r"\b(?:19[89]\d|20[0-4]\d)\b"
    r"|\b(?:january|february|march|april|june|july|august|september|october|november|december"
    r"|monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b"
    rf"|\b(?:{_MONTH_OR_DAY})\.?(?=,?\s?(?:\d|(?:{_MONTH_OR_DAY})\b))"
    rf"|(?<=\d )(?:{_MONTH_OR_DAY})\b|(?<=\d)(?:{_MONTH_OR_DAY})\b",
    re.IGNORECASE,
)


def without_dates(text: str) -> str:
    return DATE_WORDS.sub(" ", text)


def body_text(record: dict) -> str:
    """The body a reader sees: the visible HTML text, or the plain-text part when the HTML shows almost nothing."""
    html = record.get("html") or ""
    if html:
        visible = visible_html(html).text
        if len(visible.split()) >= MIN_VISIBLE_WORDS:
            # The HTML keeps the source's names in URLs and addresses for the link features; masked here as in the
            # plain-text part, or 5.6% of the legitimate mail would show `apache` to the text models.
            return mask_source_names(visible)
    return record.get("text") or ""


def email_text(record: dict) -> str:
    return without_dates(f"{record.get('subject') or ''}\n{body_text(record)[:TEXT_CHARS]}")


def _first_chars(texts):
    return [t[:CHAR_NGRAM_CHARS] for t in texts]


def course_model() -> Pipeline:
    """The course project's configuration (week 5 notebook), unchanged."""
    vectorizer = TfidfVectorizer(
        max_features=10_000, stop_words="english", ngram_range=(1, 2), min_df=5, max_df=0.95, sublinear_tf=True
    )
    return Pipeline([("tfidf", vectorizer), ("lr", LogisticRegression(max_iter=1000, solver="liblinear"))])


def text_vectorizer():
    words = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=200_000, sublinear_tf=True, dtype=np.float32)
    chars = Pipeline(
        [
            ("cut", FunctionTransformer(_first_chars)),
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(3, 5),
                    min_df=3,
                    max_features=300_000,
                    sublinear_tf=True,
                    dtype=np.float32,
                ),
            ),
        ]
    )
    return make_union(words, chars)


def text_classifier() -> LogisticRegression:
    # The dual solver is the fast one when there are far more features than emails.
    return LogisticRegression(C=4.0, max_iter=2000, solver="liblinear", dual=True)


def text_model() -> Pipeline:
    return Pipeline([("tfidf", text_vectorizer()), ("lr", text_classifier())])


class DropEmptyColumns(BaseEstimator, TransformerMixin):
    """Drop columns that are missing for every training row (e.g. header features on a text-only dataset).

    The trees handle NaN values, but not a column with no values at all.
    """

    def fit(self, x, y=None):
        self.keep_ = ~np.isnan(np.asarray(x, dtype=float)).all(axis=0)
        return self

    def transform(self, x):
        return np.asarray(x, dtype=float)[:, self.keep_]


def tree_model() -> Pipeline:
    trees = HistGradientBoostingClassifier(
        max_iter=400, learning_rate=0.05, max_leaf_nodes=31, l2_regularization=1.0, random_state=SEED
    )
    return Pipeline([("drop_empty", DropEmptyColumns()), ("trees", trees)])


def calibrate(model, x_val, y_val) -> CalibratedClassifierCV:
    """Isotonic calibration fitted on validation data only; the model itself is not refitted."""
    return CalibratedClassifierCV(FrozenEstimator(model), method="isotonic").fit(x_val, y_val)


@dataclass
class Fitted:
    """Every baseline fitted on one training split, ready to score other emails."""

    course: Pipeline
    text: Pipeline
    features: Pipeline
    stacked: Pipeline
    text_calibrated: CalibratedClassifierCV  # on the TF-IDF matrix
    stacked_calibrated: CalibratedClassifierCV

    def scores(self, texts: list[str], feature_rows: np.ndarray) -> dict[str, np.ndarray]:
        x_text = self.text.named_steps["tfidf"].transform(texts)  # vectorize once for every text-based score
        text_score = self.text.named_steps["lr"].predict_proba(x_text)[:, 1]
        stacked_x = np.column_stack([feature_rows, text_score])
        return {
            "course": self.course.predict_proba(texts)[:, 1],
            "text": text_score,
            "features": self.features.predict_proba(feature_rows)[:, 1],
            "stacked": self.stacked.predict_proba(stacked_x)[:, 1],
            "text_calibrated": _break_ties(self.text_calibrated.predict_proba(x_text)[:, 1], text_score),
            "stacked_calibrated": _break_ties(
                self.stacked_calibrated.predict_proba(stacked_x)[:, 1], self.stacked.predict_proba(stacked_x)[:, 1]
            ),
        }


def _break_ties(calibrated: np.ndarray, raw: np.ndarray) -> np.ndarray:
    """Isotonic calibration is a step function, so many emails share one probability (often exactly 1.0) and a
    single legitimate email in a tie hides the whole group from "recall at 0.1% FPR". Ordering ties by the
    uncalibrated score keeps the model's ranking; the shift (at most 1e-6) leaves the probabilities unchanged.
    """
    return calibrated * (1 - 1e-6) + raw * 1e-6


def fit_all(
    train_texts: list[str],
    train_features: np.ndarray,
    y_train: np.ndarray,
    val_texts: list[str],
    val_features: np.ndarray,
    y_val: np.ndarray,
) -> Fitted:
    course = course_model().fit(train_texts, y_train)
    vectorizer = text_vectorizer().fit(train_texts)
    x_train, x_val = vectorizer.transform(train_texts), vectorizer.transform(val_texts)
    classifier = text_classifier().fit(x_train, y_train)
    text = Pipeline([("tfidf", vectorizer), ("lr", classifier)])
    features = tree_model().fit(train_features, y_train)

    folds = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    oof_text = cross_val_predict(text_classifier(), x_train, y_train, cv=folds, method="predict_proba")[:, 1]
    stacked = tree_model().fit(np.column_stack([train_features, oof_text]), y_train)

    val_stacked_x = np.column_stack([val_features, classifier.predict_proba(x_val)[:, 1]])
    return Fitted(
        course=course,
        text=text,
        features=features,
        stacked=stacked,
        text_calibrated=calibrate(classifier, x_val, y_val),
        stacked_calibrated=calibrate(stacked, val_stacked_x, y_val),
    )
