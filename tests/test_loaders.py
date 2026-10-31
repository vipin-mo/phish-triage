import io
import tarfile
from pathlib import Path

from phish_triage.data.loaders import iter_source
from phish_triage.data.sources import RemoteFile, Source

FIXTURES = Path(__file__).parent / "fixtures"
EMAILS = sorted(FIXTURES.glob("*.eml"))


def _source(fmt: str, filename: str, label: str = "phish") -> Source:
    return Source(
        name="t",
        description="",
        license="",
        homepage="",
        attribution="",
        fmt=fmt,
        files=(RemoteFile("https://unused.example/", filename, label),),
    )


def test_mbox_yields_every_message_with_its_label(tmp_path):
    (tmp_path / "t").mkdir()
    with (tmp_path / "t" / "box.mbox").open("wb") as box:
        for path in EMAILS:
            box.write(b"From MAILER-DAEMON Thu Jan  1 00:00:00 2024\n" + path.read_bytes() + b"\n")
    messages = list(iter_source(_source("mbox", "box.mbox"), tmp_path))
    assert len(messages) == len(EMAILS)
    assert {label for _, label, _ in messages} == {"phish"}
    assert messages[0][2] == "box.mbox#0"


def test_tar_eml_reads_only_eml_members(tmp_path):
    (tmp_path / "t").mkdir()
    with tarfile.open(tmp_path / "t" / "pot.tar.gz", "w:gz") as archive:
        for path in EMAILS:
            archive.add(path, arcname=f"repo/email/{path.name}")
        readme = b"not an email"
        info = tarfile.TarInfo("repo/README.md")
        info.size = len(readme)
        archive.addfile(info, io.BytesIO(readme))
    messages = list(iter_source(_source("tar-eml", "pot.tar.gz"), tmp_path))
    assert len(messages) == len(EMAILS)
    assert all(origin.endswith(".eml") for _, _, origin in messages)


def test_tar_maildir_skips_the_cmds_file(tmp_path):
    (tmp_path / "t").mkdir()
    with tarfile.open(tmp_path / "t" / "ham.tar.bz2", "w:bz2") as archive:
        archive.add(EMAILS[0], arcname="easy_ham/00001.abc")
        archive.add(EMAILS[1], arcname="easy_ham/cmds")
    messages = list(iter_source(_source("tar-maildir", "ham.tar.bz2", "legit"), tmp_path))
    assert [origin for _, _, origin in messages] == ["ham.tar.bz2:easy_ham/00001.abc"]


def test_missing_file_has_a_helpful_error(tmp_path):
    try:
        list(iter_source(_source("mbox", "absent.mbox"), tmp_path))
    except FileNotFoundError as exc:
        assert "make data-download" in str(exc)
    else:
        raise AssertionError("expected FileNotFoundError")
