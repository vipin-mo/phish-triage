"""Download the raw datasets into data/raw/ and check them against pinned SHA-256 checksums.

    python -m phish_triage.data.download                 # every source
    python -m phish_triage.data.download nazario apache  # some sources
    python -m phish_triage.data.download --pin           # record checksums after a first download

Files that already exist and match their pinned checksum are skipped, so re-running is cheap.
Each source directory gets a MANIFEST.json with the URL, size, checksum and download time of every file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from phish_triage.data.sources import SOURCES, RemoteFile, Source

RAW_DIR = Path("data/raw")
CHECKSUMS_PATH = Path(__file__).with_name("checksums.json")
USER_AGENT = "phish-triage-dataset-builder/0.1 (+https://github.com/vipin-mo/phish-triage)"
RETRIES = 3


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_checksums() -> dict[str, dict[str, str]]:
    return json.loads(CHECKSUMS_PATH.read_text()) if CHECKSUMS_PATH.exists() else {}


def fetch(url: str, dest: Path) -> None:
    """Stream url to dest atomically (via a .part file), retrying transient errors with backoff."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    for attempt in range(1, RETRIES + 1):
        try:
            # Only the fixed https URLs from sources.py are fetched here; never URLs found inside emails.
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
            with urllib.request.urlopen(request, timeout=120) as response, part.open("wb") as out:  # noqa: S310
                while chunk := response.read(1 << 20):
                    out.write(chunk)
            part.replace(dest)
            return
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            if attempt == RETRIES:
                raise
            wait = 5 * attempt
            print(f"  retry {attempt}/{RETRIES - 1} in {wait}s: {exc}", file=sys.stderr)
            time.sleep(wait)


def download_source(source: Source, pinned: dict[str, str]) -> tuple[dict[str, dict], list[str]]:
    """Download every file of one source. Returns its manifest entries and any checksum problems."""
    manifest, problems = {}, []
    for i, remote in enumerate(source.files, 1):
        dest = RAW_DIR / source.name / remote.filename
        expected = pinned.get(remote.filename)
        if dest.exists() and (expected is None or sha256_file(dest) == expected):
            status = "cached"
        else:
            fetch(remote.url, dest)
            status = "downloaded"
            time.sleep(source.seconds_between_requests)
        actual = sha256_file(dest)
        if expected and actual != expected:
            problems.append(f"{source.name}/{remote.filename}: checksum changed")
        manifest[remote.filename] = _entry(remote, dest, actual)
        if status == "downloaded" or i == len(source.files):
            print(f"  [{i}/{len(source.files)}] {status} {remote.filename}")
    return manifest, problems


def _entry(remote: RemoteFile, dest: Path, sha: str) -> dict:
    return {
        "url": remote.url,
        "label": remote.label,
        "bytes": dest.stat().st_size,
        "sha256": sha,
        "checked_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("sources", nargs="*", help=f"any of: {', '.join(SOURCES)} (default: all)")
    parser.add_argument("--pin", action="store_true", help="write the current checksums to checksums.json")
    args = parser.parse_args(argv)
    if unknown := set(args.sources) - set(SOURCES):
        parser.error(f"unknown source(s): {', '.join(sorted(unknown))}")

    checksums = load_checksums()
    failed = False
    for name in args.sources or list(SOURCES):
        source = SOURCES[name]
        print(f"{name}: {len(source.files)} files")
        manifest, problems = download_source(source, checksums.get(name, {}))
        (RAW_DIR / name / "MANIFEST.json").write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
        for problem in problems:
            level = "ERROR" if source.byte_stable else "warning"
            print(f"  {level}: {problem}", file=sys.stderr)
            failed |= source.byte_stable
        if args.pin:
            checksums[name] = {f: e["sha256"] for f, e in sorted(manifest.items())}
    if args.pin:
        CHECKSUMS_PATH.write_text(json.dumps(checksums, indent=1, sort_keys=True) + "\n")
        print(f"pinned checksums written to {CHECKSUMS_PATH}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
