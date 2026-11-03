import gzip
import json

from phish_triage.data import audit
from phish_triage.data.records import read_records

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
    assert list(read_records(path, {RECORD["id"]})) == [RECORD["id"]]


def test_links_to_the_source_domain_can_be_removed_for_the_shortcut_check():
    record = {
        **RECORD,
        "urls": ["https://tomcat.apache.org/a", "http://198.51.100.7/login"],
        "html": '<a href="https://tomcat.apache.org/a">docs</a> <a href="http://198.51.100.7/login">log in</a>',
    }
    assert audit.link_domains(record) == ["198.51.100.7", "apache.org"]
    stripped = audit.without_source_domains(record)
    assert stripped["urls"] == ["http://198.51.100.7/login"] and 'href=""' in stripped["html"]
    assert audit.link_domains(stripped) == ["198.51.100.7"]
