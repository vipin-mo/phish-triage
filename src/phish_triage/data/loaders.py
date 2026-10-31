"""Read every downloaded source as (raw bytes, label, origin) without unpacking anything to disk."""

from __future__ import annotations

import mailbox
import tarfile
from collections.abc import Iterator
from pathlib import Path

from phish_triage.data.sources import Source

RawMessage = tuple[bytes, str, str]  # raw bytes, label, origin


def iter_source(source: Source, raw_dir: Path) -> Iterator[RawMessage]:
    reader = {"mbox": _iter_mbox, "tar-maildir": _iter_tar, "tar-eml": _iter_tar}[source.fmt]
    for remote in source.files:
        path = raw_dir / source.name / remote.filename
        if not path.exists():
            raise FileNotFoundError(f"{path} is missing; run `make data-download` first")
        for raw, origin in reader(path, source.fmt):
            yield raw, remote.label, f"{remote.filename}{origin}"


def _iter_mbox(path: Path, _fmt: str) -> Iterator[tuple[bytes, str]]:
    box = mailbox.mbox(path, create=False)
    try:
        for index, key in enumerate(box.iterkeys()):
            yield box.get_bytes(key), f"#{index}"
    finally:
        box.close()


def _iter_tar(path: Path, fmt: str) -> Iterator[tuple[bytes, str]]:
    with tarfile.open(path, "r:*") as archive:
        for member in archive:
            if not member.isfile() or not _is_message(member.name, fmt):
                continue
            extracted = archive.extractfile(member)
            if extracted is not None:
                yield extracted.read(), f":{member.name}"


def _is_message(name: str, fmt: str) -> bool:
    base = name.rsplit("/", 1)[-1]
    if fmt == "tar-eml":
        return base.lower().endswith(".eml")
    # SpamAssassin maildirs: one message per file, plus a "cmds" file that is not a message.
    return base != "cmds" and not base.startswith(".")
