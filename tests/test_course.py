import csv
import io
import zipfile

import numpy as np
import pytest

from phish_triage.data import course
from phish_triage.evaluation.course import scores_at_half


def _zip(tmp_path):
    path = tmp_path / "course.zip"
    with zipfile.ZipFile(path, "w") as archive:
        out = io.StringIO()
        csv.writer(out).writerows([["text_combined", "label"], ["verify account now", "1"], ["meeting notes", "0"]])
        archive.writestr(course.COMBINED, out.getvalue())
        for name in course.SOURCE_FILES:
            out = io.StringIO()
            csv.writer(out).writerows([["subject", "body", "label"], [f"{name} subject", "body text", "1"]])
            archive.writestr(name, out.getvalue())
    return path


def test_combined_and_by_source(tmp_path):
    path = _zip(tmp_path)
    assert course.combined(path) == (["verify account now", "meeting notes"], [1, 0])
    texts, labels, sources = course.by_source(path)
    assert sources == list(course.SOURCE_FILES.values())
    assert texts[0] == "CEAS_08.csv subject\nbody text" and set(labels) == {1}


def test_missing_zip_says_how_to_get_it(tmp_path):
    with pytest.raises(FileNotFoundError, match="make data-download"):
        course.combined(tmp_path / "missing.zip")


def test_scores_at_half():
    y = np.array([1, 1, 1, 0, 0])
    s = scores_at_half(y, np.array([0.9, 0.6, 0.4, 0.7, 0.1]))
    assert (s["precision"], s["recall"], s["false_alarm_rate"]) == (round(2 / 3, 4), round(2 / 3, 4), 0.5)
    only_phish = scores_at_half(np.array([1, 1]), np.array([0.9, 0.2]))
    assert only_phish["recall"] == 0.5 and only_phish["recall_at_1pct_fpr"] is None
