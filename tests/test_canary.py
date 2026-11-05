import io
import json
import logging
from pathlib import Path

from fastapi.testclient import TestClient

from phish_triage.service import api, smoke
from phish_triage.service.scanner import ScanResult
from phish_triage.service.store import MemoryStore

FIXTURES = Path(__file__).parent / "fixtures"
EMAIL = b"From: Bank <alerts@bank.example>\nTo: me@example.com\nSubject: Verify now\n\nZQX-secret-body verify here\n"


class Scanner:
    def __init__(self, version="v1", verdicts=None):
        self.version, self.verdicts, self.rules_version = version, verdicts or {}, 3

    def scan(self, raw):
        verdict = next((v for marker, v in self.verdicts.items() if marker in raw), "safe")
        return ScanResult(verdict, 0.9 if verdict == "phish" else 0.1, "distilbert", verdict == "phish", False)


def test_the_smoke_check_needs_both_test_emails_right():
    right = Scanner(verdicts={b"paypa1": "phish"})
    assert smoke.run(right, FIXTURES)["passed"]
    assert not smoke.run(Scanner(), FIXTURES)["passed"]  # the spoofed brand came back safe
    assert smoke.run(right, FIXTURES / "nowhere")["results"]["spoofed_brand.eml"]["got"] == "missing"


class FakeCodeDeploy:
    def __init__(self, description="phish-triage-scan: version 6 -> 7"):
        self.status, self.description = None, description

    def get_deployment(self, deploymentId):
        # What AWS really returns for an AppSpec given as content: its hash, not the content (the first live run of
        # the hook failed on reading it), and the description canary.py wrote
        revision = {"revisionType": "AppSpecContent", "appSpecContent": {"sha256": "0" * 64}}
        return {"deploymentInfo": {"revision": revision, "description": self.description}}

    def put_lifecycle_event_hook_execution_status(self, **kwargs):
        self.status = kwargs["status"]


class FakeLambda:
    def __init__(self, answer, error=None):
        self.answer, self.error, self.called = answer, error, None

    def invoke(self, FunctionName, Qualifier, Payload):
        self.called = (FunctionName, Qualifier, json.loads(Payload))
        out = {"Payload": io.BytesIO(json.dumps(self.answer).encode())}
        return out | ({"FunctionError": self.error} if self.error else {})


def test_the_hook_passes_only_a_version_whose_smoke_check_passed():
    from phish_triage.service.lambda_handler import before_traffic

    event = {"DeploymentId": "d-1", "LifecycleEventHookExecutionId": "h-1"}
    for answer, error, expected in [
        ({"passed": True}, None, "Succeeded"),
        ({"passed": False}, None, "Failed"),
        ({"errorMessage": "boom"}, "Unhandled", "Failed"),
    ]:
        codedeploy, lam = FakeCodeDeploy(), FakeLambda(answer, error)
        assert before_traffic(event, None, codedeploy, lam)["status"] == expected == codedeploy.status
        assert lam.called == ("phish-triage-scan", "7", {"source": "phish-triage.smoke"})
    # anything unexpected still reports a status, so the deployment never waits for the hook's timeout
    unreadable = FakeCodeDeploy(description="something else")
    assert before_traffic(event, None, unreadable, FakeLambda({"passed": True}))["status"] == "Failed"
    assert unreadable.status == "Failed"


def test_shadow_mode_logs_both_verdicts_and_never_changes_the_answer(caplog):
    store = MemoryStore()
    key = store.add_key("tester")
    live, shadow = Scanner("live-1", {b"ZQX": "phish"}), Scanner("shadow-1")
    c = TestClient(api.create_app(lambda: live, store, explanations=False, shadow_factory=lambda: shadow))
    with caplog.at_level(logging.INFO, logger="phish_triage.api"):
        r = c.post("/v1/scan", content=EMAIL, headers={"x-api-key": key})
    assert r.json()["verdict"] == "phish" and r.json()["model_version"] == "live-1"
    lines = [json.loads(x.getMessage()) for x in caplog.records if '"event": "shadow"' in x.getMessage()]
    assert lines == [
        {
            "event": "shadow",
            "live": {"verdict": "phish", "score": 0.9, "stage": "distilbert"},
            "shadow": {"verdict": "safe", "score": 0.1, "stage": "distilbert"},
            "shadow_version": "shadow-1",
        }
    ]
    assert "ZQX" not in caplog.text


def _canary_script():
    import importlib.util

    spec = importlib.util.spec_from_file_location("canary", Path(__file__).parents[1] / "scripts" / "canary.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeAlias:
    def __init__(self, version):
        self.version = version

    def get_alias(self, FunctionName, Name):
        return {"FunctionVersion": self.version}


class FakeDeployments:
    def __init__(self, states):
        self.states, self.created = list(states), None

    def create_deployment(self, **kwargs):
        self.created = kwargs
        return {"deploymentId": "d-9"}

    def get_deployment(self, deploymentId):
        state = self.states.pop(0)
        return {"deploymentInfo": {"status": state, "errorInformation": {"message": "alarm"}}}


def test_the_canary_moves_the_alias_through_codedeploy_with_the_smoke_hook():
    canary = _canary_script()
    deployments = FakeDeployments(["Created", "InProgress", "InProgress", "Succeeded"])
    assert canary.deploy(FakeAlias("3"), deployments, "4", sleep=lambda s: None) == "Succeeded"
    spec = json.loads(deployments.created["revision"]["appSpecContent"]["content"])
    assert spec["Resources"][0]["scan"]["Properties"] == {
        "Name": "phish-triage-scan",
        "Alias": "live",
        "CurrentVersion": "3",
        "TargetVersion": "4",
    }
    assert spec["Hooks"] == [{"BeforeAllowTraffic": "CodeDeployHook_phish-triage-smoke"}]
    assert deployments.created["description"] == "phish-triage-scan: version 3 -> 4"  # what the hook reads
    stopped = FakeDeployments(["InProgress", "Stopped"])
    assert canary.deploy(FakeAlias("3"), stopped, "4", sleep=lambda s: None) == "Stopped"
    nothing = FakeDeployments([])
    assert canary.deploy(FakeAlias("4"), nothing, "4") == "Succeeded" and nothing.created is None


class FlakyDeployments(FakeDeployments):
    def __init__(self, states, failures):
        super().__init__(states)
        self.failures = failures

    def get_deployment(self, deploymentId):
        if self.failures:
            self.failures -= 1
            raise ConnectionError("network dropped")
        return super().get_deployment(deploymentId)


def test_a_dropped_status_read_is_retried_not_fatal():
    canary = _canary_script()
    flaky = FlakyDeployments(["InProgress", "Succeeded"], failures=2)
    assert canary.deploy(FakeAlias("3"), flaky, "4", sleep=lambda s: None) == "Succeeded"
    import pytest

    dead = FlakyDeployments([], failures=canary.MAX_MISSES)
    with pytest.raises(ConnectionError):
        canary.deploy(FakeAlias("3"), dead, "4", sleep=lambda s: None)
