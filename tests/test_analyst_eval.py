import csv

import pytest

from phish_triage.evaluation import analyst_eval


def _rows():
    rows = []
    for i, label in enumerate(["phish", "phish", "legit", "legit"]):
        rows.append(
            {
                "id": f"e{i}",
                "label": label,
                "classifier_flagged": str(label == "phish"),
                "verdict": "phish" if label == "phish" else "safe",
                "suggestion": "",
                "summary": f"summary {i}",
                "action": "block and report" if label == "phish" else "no action",
                "indicators": f"[link] x{i} -> y",
                "dropped": 0,
                "_shown": "email text",
                "_signals": ["a signal"],
            }
        )
    return rows


@pytest.fixture
def sheet(tmp_path, monkeypatch):
    monkeypatch.setattr(analyst_eval, "ANALYST_DIR", tmp_path)
    monkeypatch.setattr(analyst_eval, "RATING_SHEET", tmp_path / "rating_sheet.csv")
    monkeypatch.setattr(analyst_eval, "RATING_EMAILS", tmp_path / "rating_emails.md")
    return tmp_path / "rating_sheet.csv"


def _score(path, scores):
    with path.open(newline="") as f:
        rows = list(csv.DictReader(f))
    for r, s in zip(rows, scores, strict=True):
        r.update(dict(zip(analyst_eval.RUBRIC, s, strict=True)), notes="n")
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _read(path):
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def test_scores_survive_a_rewrite_only_while_the_rated_answer_is_unchanged(sheet):
    rows = _rows()
    analyst_eval.write_rating_sheet(rows, n=4)
    _score(sheet, [("3", "3", "3", "3"), ("2", "3", "3", "3"), ("3", "3", "3", "2"), ("3", "3", "3", "3")])
    rows[1]["verdict"] = "suspicious"  # the cascade changed the final verdict, the analyst's text did not
    rows[2]["action"] = "warn the user"
    analyst_eval.write_rating_sheet(rows, n=4)
    assert [r["correct"] for r in _read(sheet)] == ["3", "", "", "3"]


def test_summary_is_split_by_label(sheet):
    analyst_eval.write_rating_sheet(_rows(), n=4)
    _score(sheet, [("3", "3", "3", "3"), ("2", "3", "3", "3"), ("3", "3", "3", "2"), ("3", "3", "3", "3")])
    s = analyst_eval.summarize_ratings(sheet)
    assert s["rated"] == 4 and s["correct"] == 2.75 and s["all_three_on_every_criterion"] == 2
    assert s["by_label"]["phish"]["correct"] == 2.5 and s["by_label"]["legit"]["useful"] == 2.5


def test_a_line_added_above_the_header_is_reported_not_silently_misread(sheet):
    analyst_eval.write_rating_sheet(_rows(), n=4)
    sheet.write_text("rating_sheet\r\n" + sheet.read_text())
    with pytest.raises(SystemExit, match="header row"):
        analyst_eval.summarize_ratings(sheet)


def test_scores_outside_one_to_three_are_rejected(sheet):
    analyst_eval.write_rating_sheet(_rows(), n=4)
    _score(sheet, [("3", "3", "3", "3"), ("4", "3", "3", "3"), ("3", "3", "3", "3"), ("", "x", "", "")])
    with pytest.raises(SystemExit, match="rows 2, 4"):
        analyst_eval.summarize_ratings(sheet)
