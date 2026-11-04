"""Put the Anthropic API key from .env into the service's Secrets Manager secret (`make put-anthropic-key`).

The key never appears on a command line, in output or in Terraform: it's read from .env here and sent straight to
Secrets Manager, so only the scan function can read it (infra/service). Needs the MFA session (`AWS_ENV`).
"""

from __future__ import annotations

import sys

import boto3

from phish_triage.config import load_env

SECRET_NAME = "phish-triage/anthropic-api-key"  # noqa: S105 - the secret's name (infra/service), not a key


def main() -> int:
    import os

    load_env()
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not key.startswith("sk-ant-"):
        print("no Anthropic key in .env (ANTHROPIC_API_KEY)", file=sys.stderr)
        return 1
    version = boto3.client("secretsmanager").put_secret_value(SecretId=SECRET_NAME, SecretString=key)["VersionId"]
    print(f"stored a new version of {SECRET_NAME} ({version[:8]}...); the key itself is not shown")
    return 0


if __name__ == "__main__":
    sys.exit(main())
