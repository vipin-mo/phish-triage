import gzip
import json

from phish_triage.data import audit

RECORD = {
    "id": "abcdef0123456789",
    "source": "t",
    "label": "phish",
    "date": "2024-03-05T00:00:00+00:00",
    "subject": "Hi",
    "text": "Body",
    "headers": [
        ["Received", "from a by b"],
        ["Authentication-Results", "mx.receiver.test; spf=pass"],
        ["To", "Ann <ann@receiver.test>"],
        ["Message-ID", "<1@mailer.test>"],
    ],
}


def test_cheat_feature_groups():
    assert audit.header_names(RECORD) == ["authentication-results", "message-id", "received", "to"]
    assert audit.header_order(RECORD)[0] == "received > authentication-results"
    assert audit.recipient_domain(RECORD) == ["to:receiver.test"]
    assert "mx.receiver.test" in audit.auth_server(RECORD)
    assert audit.message_id_domain(RECORD) == ["mailer.test"]
    assert audit.date(RECORD) == ["year:2024", "month:03"]
    assert audit.auth_server({**RECORD, "headers": []}) == ["absent"]


def test_read_selects_records_by_id_prefix(tmp_path):
    path = tmp_path / "r.jsonl.gz"
    other = {**RECORD, "id": "ffffffffffffffff"}
    with gzip.open(path, "wt") as out:
        out.write(json.dumps(RECORD) + "\n" + json.dumps(other) + "\n")
    assert list(audit.read(path, {RECORD["id"]})) == [RECORD["id"]]
