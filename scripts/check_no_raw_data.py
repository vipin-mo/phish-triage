"""Fail if any raw email or dataset file is about to be committed.

Runs as a pre-commit hook (on staged files) and in CI (on every tracked file),
so raw mail cannot reach the public repo even if .gitignore is bypassed with -f.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import PurePosixPath

BLOCKED_SUFFIXES = {".eml", ".mbox", ".msg", ".mbx", ".pst", ".7z", ".gz", ".tgz", ".zip", ".parquet", ".csv"}
ALLOWED_IN_DATA = {"data/README.md"}
# Hand-made test emails are allowed: they are synthetic and reviewed.
ALLOWED_PREFIXES = ("tests/fixtures/",)


def violations(paths: list[str]) -> list[str]:
    bad = []
    for raw in paths:
        path = PurePosixPath(raw)
        if raw.startswith(ALLOWED_PREFIXES):
            continue
        if path.parts and path.parts[0] == "data" and raw not in ALLOWED_IN_DATA:
            bad.append(f"{raw}: files under data/ are never committed")
        elif path.suffix.lower() in BLOCKED_SUFFIXES:
            bad.append(f"{raw}: {path.suffix} files look like raw data")
    return bad


def main(argv: list[str]) -> int:
    paths = argv
    if not paths:
        # Fixed argument list, no shell: S603/S607 do not apply.
        tracked = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True)  # noqa: S603, S607
        paths = tracked.stdout.splitlines()
    bad = violations(paths)
    for line in bad:
        print(line, file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
