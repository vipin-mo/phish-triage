import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "check_no_raw_data", Path(__file__).parents[1] / "scripts" / "check_no_raw_data.py"
)
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def test_blocks_raw_mail_anywhere():
    assert check.violations(["notes/sample.eml", "x/inbox.mbox", "y/dump.MBOX"])


def test_blocks_anything_under_data_except_readme():
    assert check.violations(["data/raw/nazario/2024.mbox", "data/processed/train.jsonl"])
    assert check.violations(["data/README.md"]) == []


def test_allows_source_and_synthetic_fixtures():
    assert check.violations(["src/phish_triage/data/loader.py", "tests/fixtures/spoofed_paypal.eml"]) == []


def test_model_files_dataset_formats_and_odd_paths_are_blocked():
    blocked = [
        "artifacts/bundle/v/stacked.joblib",
        "models/distilbert.onnx",
        "weights/model.safetensors",
        "notes/records.jsonl",
        "downloads/20021010_easy_ham.tar.bz2",
        "mlruns/mlflow.db",
        "Data/private/split.json",
        "build/bundle/bundle.json",
        "tests/fixtures/inbox.zip",
        "tests/fixtures/sub/x.eml",
    ]
    assert len(check.violations(blocked)) == len(blocked)
    assert check.violations(["tests/fixtures/spoofed_brand.eml", "src/phish_triage/api.py", "data/README.md"]) == []


def test_a_large_extensionless_file_is_blocked(tmp_path):
    (tmp_path / "phishing-2015").write_bytes(b"x" * (check.MAX_BYTES + 1))
    (tmp_path / "small.py").write_text("x = 1\n")
    assert check.violations(["phishing-2015", "small.py"], tmp_path) == [
        f"phishing-2015: {check.MAX_BYTES + 1:,} bytes is too large for code or a report"
    ]


def test_only_the_demo_gif_may_be_larger_and_only_up_to_its_own_limit(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "demo.gif").write_bytes(b"x" * (check.MAX_BYTES + 1))
    (tmp_path / "docs" / "other.gif").write_bytes(b"x" * (check.MAX_BYTES + 1))
    assert check.violations(["docs/demo.gif", "docs/other.gif"], tmp_path) == [
        f"docs/other.gif: {check.MAX_BYTES + 1:,} bytes is too large for code or a report"
    ]
    (tmp_path / "docs" / "demo.gif").write_bytes(b"x" * (check.SIZE_LIMITS["docs/demo.gif"] + 1))
    assert check.violations(["docs/demo.gif"], tmp_path)
