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
