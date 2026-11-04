"""Create an API key for the deployed service.

    python -m phish_triage.service.keys create --owner vipin    # needs AWS credentials (the phish-triage profile)

The key is printed once and only its SHA-256 is written to the keys table, so it can't be shown again: a lost key
is replaced with a new one.
"""

from __future__ import annotations

import argparse
import sys

from phish_triage.service.store import hash_key, new_api_key
from phish_triage.service.store_dynamo import DynamoStore

PREFIX = "phish-triage"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="create a key and print it once")
    create.add_argument("--owner", required=True, help="who the key is for, as it will appear in the logs")
    create.add_argument("--prefix", default=PREFIX)
    args = parser.parse_args(argv)
    api_key = new_api_key()
    DynamoStore(args.prefix).add_key_hash(hash_key(api_key), args.owner)
    print(f"API key for {args.owner} (shown once, store it somewhere safe): {api_key}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
