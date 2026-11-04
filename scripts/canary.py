"""Move the `live` alias to the newly published version through CodeDeploy (`make deploy-apply` runs this).

    python scripts/canary.py    # needs the MFA session (`AWS_ENV`) and Terraform's outputs

Terraform publishes a new version of the scan function with each image but leaves the alias where it is. This starts
a CodeDeploy deployment from the alias's version to the newest one: first the BeforeAllowTraffic hook runs the smoke
check on the new version (`service/smoke.py`, which also loads its model), then 10% of traffic goes to it for 10
minutes, then all of it. The error, server-error and slowness alarms roll it back automatically. It waits for the
end and exits 1 unless the deployment succeeded.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time

FUNCTION, ALIAS = "phish-triage-scan", "live"
APP, GROUP, HOOK = "phish-triage", "phish-triage-scan", "CodeDeployHook_phish-triage-smoke"
DONE = {"Succeeded", "Failed", "Stopped"}


def appspec(current: str, target: str) -> str:
    return json.dumps(
        {
            "version": 0.0,
            "Resources": [
                {
                    "scan": {
                        "Type": "AWS::Lambda::Function",
                        "Properties": {
                            "Name": FUNCTION,
                            "Alias": ALIAS,
                            "CurrentVersion": current,
                            "TargetVersion": target,
                        },
                    }
                }
            ],
            "Hooks": [{"BeforeAllowTraffic": HOOK}],
        }
    )


def newest_version() -> str:
    # Fixed argument list, no shell: S603/S607 do not apply.
    out = subprocess.run(  # noqa: S603
        ["terraform", "-chdir=infra/service", "output", "-raw", "scan_version"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.strip()


def deploy(lambda_client, codedeploy, target: str, poll_seconds: int = 20, sleep=time.sleep) -> str:
    current = lambda_client.get_alias(FunctionName=FUNCTION, Name=ALIAS)["FunctionVersion"]
    if current == target:
        print(f"the alias already points at version {target}; nothing to deploy")
        return "Succeeded"
    deployment = codedeploy.create_deployment(
        applicationName=APP,
        deploymentGroupName=GROUP,
        revision={"revisionType": "AppSpecContent", "appSpecContent": {"content": appspec(current, target)}},
        description=f"version {current} -> {target}",
    )["deploymentId"]
    print(f"{deployment}: version {current} -> {target} (smoke check, then 10% for 10 minutes)", flush=True)
    last = None
    while True:
        info = codedeploy.get_deployment(deploymentId=deployment)["deploymentInfo"]
        if info["status"] != last:
            print(f"  {info['status']}", flush=True)
            last = info["status"]
        if info["status"] in DONE:
            if info["status"] != "Succeeded":
                print(f"  {info.get('errorInformation', {}).get('message', '')}", flush=True)
            return info["status"]
        sleep(poll_seconds)


def main() -> int:
    import boto3

    status = deploy(boto3.client("lambda"), boto3.client("codedeploy"), newest_version())
    return 0 if status == "Succeeded" else 1


if __name__ == "__main__":
    sys.exit(main())
