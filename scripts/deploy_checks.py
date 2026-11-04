"""Checks the laptop deploy runs between its steps (`make deploy-*`), so a broken deploy stops instead of passing.

    python scripts/deploy_checks.py session          # the MFA session has at least 30 minutes left
    python scripts/deploy_checks.py clean-main       # the tree is clean (untracked files too) and HEAD is origin/main
    python scripts/deploy_checks.py loaded FILE...   # the warm-up or /v1/health answered with infra/bundle-version

Each one exits 1 with a reason. Without them, an expired session could stop Terraform halfway (state not written,
the lock held), an image could be tagged with a commit it doesn't contain, and a deploy whose model failed to load
still printed success.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

MIN_SESSION_MINUTES = 30
BUNDLE_VERSION = Path("infra/bundle-version")


def git(*args: str) -> str:
    # Fixed argument list, no shell: S603/S607 do not apply.
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout.strip()  # noqa: S603, S607


def session(expiration: str | None, now: datetime | None = None) -> str | None:
    """`AWS_CREDENTIAL_EXPIRATION`, as `aws configure export-credentials` sets it."""
    if not expiration:
        return None  # long-lived credentials don't expire
    left = datetime.fromisoformat(expiration.replace("Z", "+00:00")) - (now or datetime.now(UTC))
    minutes = left.total_seconds() / 60
    if minutes < MIN_SESSION_MINUTES:
        return f"the AWS session ends in {max(minutes, 0):.0f} min; sign in again first (Terraform can't refresh it)"
    return None


def clean_main() -> str | None:
    if dirty := git("status", "--porcelain"):
        return f"the tree has changes or untracked files ({len(dirty.splitlines())}); the image would not match HEAD"
    git("fetch", "--quiet", "origin", "main")
    if git("rev-parse", "HEAD") != git("rev-parse", "origin/main"):
        return "HEAD is not origin/main; deploy the merged commit (or DEV=1 for a test image)"
    return None


def loaded(paths: list[str]) -> str | None:
    expected = BUNDLE_VERSION.read_text().strip()
    for path in paths:
        answer = json.loads(Path(path).read_text() or "{}")
        if answer.get("FunctionError"):
            return f"{path}: the function failed ({answer['FunctionError']}); see its logs"
        if "StatusCode" in answer:  # the invoke's own metadata, not the function's answer
            continue
        if answer.get("model_version") != expected:
            return f"{path}: model {answer.get('model_version')} is loaded, infra/bundle-version is {expected}"
    return None


def main(argv: list[str]) -> int:
    command, rest = argv[0], argv[1:]
    if command == "session":
        problem = session(os.environ.get("AWS_CREDENTIAL_EXPIRATION"))
    elif command == "clean-main":
        problem = clean_main()
    elif command == "loaded":
        problem = loaded(rest)
    else:
        problem = f"unknown check {command}"
    if problem:
        print(f"deploy check failed: {problem}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
