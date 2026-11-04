import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "deploy_checks", Path(__file__).parents[1] / "scripts" / "deploy_checks.py"
)
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


def test_a_session_ending_soon_stops_the_deploy():
    now = datetime(2026, 11, 4, 8, 0, tzinfo=UTC)
    assert checks.session("2026-11-04T08:10:00+00:00", now)
    assert checks.session("2026-11-04T11:56:20Z", now) is None
    assert checks.session(None, now) is None


def test_a_deploy_whose_model_did_not_load_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(checks, "BUNDLE_VERSION", tmp_path / "bundle-version")
    checks.BUNDLE_VERSION.write_text("with-newsletters-1\n")

    def write(name: str, answer: dict) -> str:
        (tmp_path / name).write_text(json.dumps(answer))
        return str(tmp_path / name)

    ok = [
        write("invoke.json", {"StatusCode": 200}),
        write("warm.json", {"warm": True, "model_version": "with-newsletters-1"}),
    ]
    assert checks.loaded(ok) is None
    assert "failed" in checks.loaded([write("i2.json", {"StatusCode": 200, "FunctionError": "Unhandled"})])
    assert "None is loaded" in checks.loaded([write("h.json", {"status": "ok", "model_version": None})])
    assert "with-inbox-1 is loaded" in checks.loaded([write("w.json", {"model_version": "with-inbox-1"})])
