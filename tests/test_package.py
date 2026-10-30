import importlib

import phish_triage


def test_version_is_set():
    assert phish_triage.__version__


def test_subpackages_import():
    for name in ("data", "features", "models", "evaluation", "service"):
        importlib.import_module(f"phish_triage.{name}")
