"""Fail if any raw email, dataset or model file is about to be committed.

Runs as a pre-commit hook (on staged files) and in CI (on every tracked file, and with `--history` on every file any
commit ever added), so raw mail and private models cannot reach the public repo even if .gitignore is bypassed with
-f, or a file is added in one commit and deleted in the next (it would stay in the public history).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path, PurePosixPath

BLOCKED_SUFFIXES = {
    # mail and archives
    *(".eml", ".mbox", ".msg", ".mbx", ".pst", ".7z", ".gz", ".tgz", ".zip", ".bz2", ".xz", ".tar"),
    # datasets and saved records
    *(".parquet", ".csv", ".jsonl", ".db", ".sqlite", ".npy", ".npz"),
    # model files: the deployed ones are trained partly on private mail
    *(".onnx", ".joblib", ".pkl", ".pickle", ".pt", ".pth", ".safetensors", ".bin"),
}
# Folders that only ever hold data, models or build output (compared without case: macOS doesn't care about it).
BLOCKED_FOLDERS = {"data", "artifacts", "mlruns", "build", "private"}
ALLOWED = {"data/README.md"}
# Hand-made test emails are allowed: they are synthetic and reviewed. Nothing else goes in the fixtures folder.
FIXTURES = "tests/fixtures/"
MAX_BYTES = 1_000_000  # nothing in the repo is near this; an extensionless corpus file (`phishing-2015`) would be
SIZE_EXEMPT = {"uv.lock"}
SIZE_LIMITS = {"docs/demo.gif": 1_500_000}  # the README's demo: a readable 25 s GIF of the add-on doesn't fit in 1 MB


def violations(paths: list[str], root: Path | None = None) -> list[str]:
    bad = []
    for raw in paths:
        path = PurePosixPath(raw)
        if raw in ALLOWED:
            continue
        if raw.startswith(FIXTURES):
            if path.suffix != ".eml" or len(path.parts) != 3:
                bad.append(f"{raw}: only hand-made .eml files belong in {FIXTURES}")
            continue
        if path.parts and path.parts[0].lower() in BLOCKED_FOLDERS:
            bad.append(f"{raw}: files under {path.parts[0]}/ are never committed")
        elif any(suffix.lower() in BLOCKED_SUFFIXES for suffix in path.suffixes):
            bad.append(f"{raw}: {''.join(path.suffixes)} files look like raw data or a model")
        elif raw not in SIZE_EXEMPT and (size := _size(root, raw)) > SIZE_LIMITS.get(raw, MAX_BYTES):
            bad.append(f"{raw}: {size:,} bytes is too large for code or a report")
    return bad


def _size(root: Path | None, raw: str) -> int:
    """0 when there is no tree to look in (the history check) or the file is gone."""
    return (root / raw).stat().st_size if root is not None and (root / raw).is_file() else 0


def git_paths(*args: str) -> list[str]:
    # Fixed argument list, no shell: S603/S607 do not apply.
    out = subprocess.run(["git", *args], capture_output=True, text=True, check=True)  # noqa: S603, S607
    return sorted({line for line in out.stdout.splitlines() if line.strip()})


def main(argv: list[str]) -> int:
    if argv == ["--history"]:
        paths = git_paths("log", "--all", "--diff-filter=A", "--name-only", "--format=")
        bad = violations(paths)
    else:
        paths = argv or git_paths("ls-files")
        bad = violations(paths, Path.cwd())
    for line in bad:
        print(line, file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
