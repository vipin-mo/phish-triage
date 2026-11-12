import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import rollback_check  # noqa: E402


class FakeLambda:
    def get_alias(self, FunctionName, Name):
        return {"FunctionVersion": "9", "RoutingConfig": {}}


class FakeCodeDeploy:
    def create_deployment(self, **kwargs):
        self.description = kwargs["description"]
        return {"deploymentId": "d-1"}

    def get_deployment(self, deploymentId):
        info = {"status": "Failed", "errorInformation": {"code": "HOOK_EXECUTION_FAILURE", "message": "smoke"}}
        return {"deploymentInfo": info | {"rollbackInfo": {"rollbackDeploymentId": "d-2"}}}

    def list_deployments(self, **kwargs):
        return {"deployments": ["d-1"]}


def test_a_stopped_bad_deployment_is_reported_with_the_alias_unchanged():
    codedeploy = FakeCodeDeploy()
    r = rollback_check.run(FakeLambda(), codedeploy, "7")
    assert codedeploy.description == "phish-triage-scan: version 9 -> 7"
    assert r["status"] == "Failed" and r["rollback"] and r["alias_before"] == r["alias_after"] == "9"
    text = rollback_check.to_markdown(r)
    assert "| Traffic sent to the bad version | none |" in text and "HOOK_EXECUTION_FAILURE" in text


class FakeLogs:
    def filter_log_events(self, **kwargs):
        lines = [
            'INFO {"event": "smoke", "version": "9", "model_version": "new", "passed": true}',
            'INFO {"event": "smoke", "version": "7", "model_version": "old", "passed": true, '
            '"error": "not the pinned bundle"}',
        ]
        return {"events": [{"message": line} for line in lines]}


def test_the_hook_log_says_what_the_bad_version_loaded():
    assert rollback_check.hook_log(FakeLogs(), "7") == {"loaded": "old", "hook_error": "not the pinned bundle"}
    assert rollback_check.hook_log(FakeLogs(), "5") == {}
