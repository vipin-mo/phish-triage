import io
import json
from pathlib import Path

from phish_triage.data import retraining
from phish_triage.service import bundle

FIXTURES = Path(__file__).parent / "fixtures"


class FakeS3:
    def __init__(self, objects):
        self.objects, self.deleted = dict(objects), []

    def get_paginator(self, name):
        objects = self.objects

        class Pages:
            def paginate(self, Bucket, Prefix):
                return [{"Contents": [{"Key": k} for k in objects if k.startswith(Prefix)]}]

        return Pages()

    def get_object(self, Bucket, Key):
        raw, label = self.objects[Key]
        return {"Body": io.BytesIO(raw), "Metadata": {"label": label}}

    def delete_object(self, Bucket, Key):
        self.deleted.append(Key)


def test_pulling_keeps_masked_records_then_deletes_them_from_the_bucket(tmp_path, monkeypatch):
    monkeypatch.setattr(retraining, "PRIVATE_DIR", tmp_path)
    monkeypatch.setattr(retraining, "MASKED", tmp_path / "masked.jsonl.gz")
    phish, safe = (FIXTURES / "spoofed_brand.eml").read_bytes(), (FIXTURES / "clean_newsletter.eml").read_bytes()
    s3 = FakeS3({"emails/vipin/a.eml": (phish, "phish"), "emails/vipin/b.eml": (safe, "legit")})
    counts = retraining.pull("bucket", s3)
    assert counts["added"] == 2 and counts["phish"] == 1 and counts["legit"] == 1
    assert sorted(s3.deleted) == ["emails/vipin/a.eml", "emails/vipin/b.eml"]  # "deleted once used"
    kept = retraining.read_masked()
    assert {r["source"] for r in kept.values()} == {"retraining"} and {r["label"] for r in kept.values()} == {
        "phish",
        "legit",
    }
    again = retraining.pull("bucket", FakeS3({"emails/vipin/c.eml": (phish, "phish")}))
    assert again["already pulled"] == 1 and again["total pulled"] == 2


def test_the_split_adds_the_emails_to_training_only():
    base = {"train": ["t1"], "val": ["v1"], "test": ["x1"]}
    split = retraining.build_split(base, ["r2", "r1", "t1"])
    assert split == {"train": ["t1", "r1", "r2"], "val": ["v1"], "test": ["x1"]}


def test_the_deployed_split_follows_infra_bundle_version(tmp_path, monkeypatch):
    version = tmp_path / "bundle-version"
    monkeypatch.setattr(bundle, "BUNDLE_VERSION_FILE", version)
    version.write_text("with-retraining-20261105-ab12cd34\n")
    assert (
        bundle._deployed_split() == "with_retraining"
        and bundle.distilbert_split("with_retraining") == "with_newsletters"
    )
    version.write_text("with-newsletters-20261104-e7f1d257\n")
    assert bundle._deployed_split() == "with_newsletters"


def test_a_sent_email_never_reaches_an_llm():
    import pytest

    from phish_triage.data.private import refuse_private

    with pytest.raises(PermissionError):
        refuse_private({"source": "retraining", "id": "x"})
    assert json.dumps(sorted(retraining.LABEL_OF)) == '["legit", "phish"]'


def test_only_the_listed_owners_emails_are_pulled(tmp_path, monkeypatch):
    monkeypatch.setattr(retraining, "PRIVATE_DIR", tmp_path)
    monkeypatch.setattr(retraining, "MASKED", tmp_path / "masked.jsonl.gz")
    phish = (FIXTURES / "spoofed_brand.eml").read_bytes()
    s3 = FakeS3({"emails/vipin/a.eml": (phish, "legit"), "emails/stranger/b.eml": (phish, "legit")})
    counts = retraining.pull("bucket", s3, allowed=("vipin",))
    assert counts["added"] == 1 and counts["other owners' emails, left in the bucket"] == 1
    assert s3.deleted == ["emails/vipin/a.eml"]  # the stranger's email is neither used nor deleted
    assert retraining.owners() == ("vipin",)  # infra/retraining-owners, which Terraform reads too


def _record(name, label="legit"):
    from phish_triage.data.mask import mask_record
    from phish_triage.data.parse import parse_email

    raw = (FIXTURES / name).read_bytes()
    return mask_record(parse_email(raw, source="retraining", label=label, origin=name).to_dict())


def test_a_sent_email_like_a_test_email_is_left_out_of_training():
    copy, other = _record("clean_newsletter.eml"), _record("spoofed_brand.eml", "phish")
    left_out = retraining.like_a_test_email({"copy": copy, "other": other}, tests=[_record("clean_newsletter.eml")])
    assert left_out == {"copy"}  # same sender and the same text as a test email; the other one is kept
    split = retraining.build_split({"train": [], "val": [], "test": ["x"]}, ["copy", "other"], left_out)
    assert split["train"] == ["other"]
