"""Fail if any raw email, dataset or model file is about to be committed.

Runs as a pre-commit hook (on staged files) and in CI (on every tracked file, and with `--history` on every file any
commit ever held), so raw mail and private models cannot reach the public repo even if .gitignore is bypassed with
-f, or a file is added in one commit and deleted in the next (it would stay in the public history). Besides names and
folders it checks each file's size and its first bytes: a file that starts like an email is blocked whatever it is
called. Secrets, Terraform state and saved plans (which hold the account ID and the alarm address) are blocked by
name; gitleaks (CI and a pre-commit hook) looks for secrets inside files.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

BLOCKED_SUFFIXES = {
    # mail and archives
    *(".eml", ".mbox", ".msg", ".mbx", ".pst", ".mht", ".mhtml"),
    *(".7z", ".gz", ".tgz", ".zip", ".bz2", ".xz", ".tar", ".rar", ".zst"),
    # datasets and saved records
    *(".parquet", ".csv", ".tsv", ".jsonl", ".db", ".sqlite", ".npy", ".npz", ".h5", ".hdf5"),
    # model files: the deployed ones are trained partly on private mail
    *(".onnx", ".joblib", ".pkl", ".pickle", ".pt", ".pth", ".safetensors", ".bin", ".ckpt", ".gguf"),
}
# Secrets, keys and Terraform's state, variables and saved plans
SECRET_SUFFIXES = {".tfstate", ".tfplan", ".tfvars", ".pem", ".key", ".p12", ".pfx", ".env"}
SECRET_NAMES = {".env", ".envrc", "tfplan", "credentials", "credentials.json", ".clasprc.json"}
SECRET_PREFIXES = ("client_secret",)  # Google's OAuth client files
# Folders that only ever hold data, models or build output (compared without case: macOS doesn't care about it).
BLOCKED_FOLDERS = {"data", "artifacts", "mlruns", "build", "private"}
ANYWHERE_FOLDERS = {".terraform", ".aws"}  # blocked at any depth
ALLOWED = {"data/README.md", ".env.example"}
HEAD_BYTES = 4096
MBOX_FROM = re.compile(rb"From \S+ +(Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ")
# A raw email starts with an mbox separator or with header lines; three of these in its first bytes is mail.
MAIL_HEADER = re.compile(
    rb"^(received|return-path|delivered-to|message-id|dkim-signature|x-gmail-labels|authentication-results|arc-seal"
    rb"|x-received|mime-version|content-type|from|to|subject|date):",
    re.IGNORECASE | re.MULTILINE,
)
# Headers only a mail server writes: three different ones at the start of lines, anywhere in the first bytes, is a
# pasted email even after a preface line. Code that builds a test email puts them inside string literals instead.
SERVER_HEADER = re.compile(
    rb"^(received|return-path|delivered-to|dkim-signature|x-gmail-labels|authentication-results|arc-seal"
    rb"|arc-message-signature|x-received|x-google-smtp-source):",
    re.IGNORECASE | re.MULTILINE,
)
# Hand-made test emails are allowed: they are synthetic and reviewed. Nothing else goes in the fixtures folder.
FIXTURES = "tests/fixtures/"
MAX_FIXTURE_BYTES = 20_000  # a hand-made test email is a few KB; a real one with images is far larger
MAX_BYTES = 1_000_000  # nothing in the repo is near this; an extensionless corpus file (`phishing-2015`) would be
SIZE_EXEMPT = {"uv.lock"}
SIZE_LIMITS = {"docs/demo.gif": 1_500_000}  # the README's demo: a readable 25 s GIF of the add-on doesn't fit in 1 MB


def looks_like_email(head: bytes) -> bool:
    first = head.lstrip()[:200]
    if MBOX_FROM.match(first):
        return True
    if len({m.lower() for m in SERVER_HEADER.findall(head)}) >= 3:
        return True
    return bool(re.match(rb"[A-Za-z-]+: ", first)) and len(MAIL_HEADER.findall(head)) >= 3


def violations(
    paths: list[str], root: Path | None = None, blobs: dict[str, list[tuple[int, bytes]]] | None = None
) -> list[str]:
    """`root`: check the files in this tree; `blobs`: path -> (size, first bytes) of every version in the history."""
    bad = []
    for raw in paths:
        path = PurePosixPath(raw)
        if raw in ALLOWED:
            continue
        versions = blobs.get(raw, []) if blobs is not None else [_read(root, raw)]
        if raw.startswith(FIXTURES):
            if path.suffix != ".eml" or len(path.parts) != 3:
                bad.append(f"{raw}: only hand-made .eml files belong in {FIXTURES}")
            elif (size := max((v[0] for v in versions), default=0)) > MAX_FIXTURE_BYTES:
                bad.append(f"{raw}: {size:,} bytes is too large for a hand-made test email")
            continue
        name = path.name.lower()
        if path.parts and path.parts[0].lower() in BLOCKED_FOLDERS:
            bad.append(f"{raw}: files under {path.parts[0]}/ are never committed")
        elif folder := next((part for part in path.parts[:-1] if part.lower() in ANYWHERE_FOLDERS), None):
            bad.append(f"{raw}: files under a {folder}/ folder are never committed")
        elif (
            name in SECRET_NAMES
            or name.startswith((".env.", *SECRET_PREFIXES))
            or any(x.lower() in SECRET_SUFFIXES for x in path.suffixes)
        ):
            bad.append(f"{raw}: looks like a secret, a key or Terraform state, variables or a plan")
        elif any(suffix.lower() in BLOCKED_SUFFIXES for suffix in path.suffixes):
            bad.append(f"{raw}: {''.join(path.suffixes)} files look like raw data or a model")
        elif raw not in SIZE_EXEMPT and (size := max((v[0] for v in versions), default=0)) > SIZE_LIMITS.get(
            raw, MAX_BYTES
        ):
            bad.append(f"{raw}: {size:,} bytes is too large for code or a report")
        elif any(looks_like_email(v[1]) for v in versions):
            bad.append(f"{raw}: starts like a raw email")
    return bad


def _read(root: Path | None, raw: str) -> tuple[int, bytes]:
    """(size, first bytes); (0, b"") when there is no tree to look in or the file is gone."""
    if root is None or not (root / raw).is_file():
        return 0, b""
    with (root / raw).open("rb") as f:
        return (root / raw).stat().st_size, f.read(HEAD_BYTES)


def staged_blobs(paths: list[str]) -> dict[str, list[tuple[int, bytes]]]:
    """path -> (size, first bytes) of what is staged, which is what gets committed: a file staged and then changed
    in the working tree must be checked as staged. Paths that aren't staged are read from the working tree."""
    out: dict[str, list[tuple[int, bytes]]] = {}
    for raw in paths:
        # Fixed argument list, no shell: S603/S607 do not apply.
        shown = subprocess.run(["git", "show", f":{raw}"], capture_output=True)  # noqa: S603, S607
        out[raw] = (
            [(len(shown.stdout), shown.stdout[:HEAD_BYTES])] if shown.returncode == 0 else [_read(Path.cwd(), raw)]
        )
    return out


def history_blobs() -> dict[str, list[tuple[int, bytes]]]:
    """Every path any commit held -> (size, first bytes) of each version of it. Read from every commit's changes, so a
    blob that also sits at another path (a raw email copied to an allowed fixture, then deleted) is checked at each."""
    # Fixed argument lists, no shell: S603/S607 do not apply.
    log = subprocess.run(  # noqa: S603
        ["git", "log", "--all", "-m", "--raw", "--no-abbrev", "--no-renames", "--format="],  # noqa: S607
        capture_output=True,
        check=True,
    ).stdout.decode()
    pairs: set[tuple[str, str]] = set()
    for line in log.splitlines():
        if line.startswith(":") and "\t" in line:
            meta, path = line.split("\t", 1)
            sha = meta.split()[3]
            if set(sha) != {"0"}:  # a deletion has no new version
                pairs.add((path, sha))
    shas = sorted({sha for _, sha in pairs})
    batch = subprocess.run(  # noqa: S603
        ["git", "cat-file", "--batch"],  # noqa: S607
        input="".join(f"{sha}\n" for sha in shas).encode(),
        capture_output=True,
        check=True,
    ).stdout
    content: dict[str, tuple[int, bytes]] = {}
    at = 0
    for sha in shas:
        header_end = batch.index(b"\n", at)
        _, kind, size = batch[at:header_end].split()
        start, size = header_end + 1, int(size)
        if kind == b"blob":
            content[sha] = (size, batch[start : start + HEAD_BYTES])
        at = start + size + 1
    blobs: dict[str, list[tuple[int, bytes]]] = {}
    for path, sha in sorted(pairs):
        if sha in content:  # submodule entries aren't blobs
            blobs.setdefault(path, []).append(content[sha])
    return blobs


def git_paths(*args: str) -> list[str]:
    # Fixed argument list, no shell: S603/S607 do not apply.
    out = subprocess.run(["git", *args], capture_output=True, text=True, check=True)  # noqa: S603, S607
    return sorted({line for line in out.stdout.splitlines() if line.strip()})


def main(argv: list[str]) -> int:
    if argv == ["--history"]:
        blobs = history_blobs()
        bad = violations(sorted(blobs), blobs=blobs)
    elif argv:  # the pre-commit hook: the staged files
        bad = violations(argv, blobs=staged_blobs(argv))
    else:
        bad = violations(git_paths("ls-files"), Path.cwd())
    for line in bad:
        print(line, file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
