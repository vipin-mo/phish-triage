import csv
import json
import mailbox

import numpy as np
import pytest

from phish_triage.evaluation import test_inbox as ti


def _message(labels: str, subject: str, sender: str = "news@shop.example") -> bytes:
    return (
        f"From: Shop <{sender}>\nTo: me@gmail.example\nSubject: {subject}\nX-Gmail-Labels: {labels}\n"
        "Date: Mon, 2 Nov 2026 10:00:00 +0000\n"
        "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=shop.example;"
        " dkim=pass header.d=shop.example; dmarc=pass\n"
        f"\nHello, {subject}.\n"
    ).encode()


def test_gmail_category_picks_the_most_specific_and_skips_my_own_mail():
    assert ti.gmail_category("Inbox,Category Updates,Category Purchases,Opened") == "purchases"
    assert ti.gmail_category("Inbox,Category Personal") == "primary"
    assert ti.gmail_category("Inbox,Important") == "primary"
    assert ti.gmail_category("Spam,Category Promotions") == "spam"
    assert ti.gmail_category("Sent,Inbox") is None
    assert ti.gmail_category("Archived") == "other"


def test_load_inbox_reads_categories_and_leaves_out_sent_mail(tmp_path):
    path = tmp_path / "inbox.mbox"
    box = mailbox.mbox(path)
    for labels, subject in (("Inbox,Category Updates", "a"), ("Spam", "b"), ("Sent", "c")):
        box.add(_message(labels, subject))
    box.close()
    records, categories, skipped = ti.load_inbox(path)
    assert categories == ["updates", "spam"] and skipped == 1
    assert [r["label"] for r in records] == ["legit", "spam"] and {r["source"] for r in records} == {"test_inbox"}


def test_report_has_no_subject_or_sender_and_review_reads_only_my_labels(tmp_path):
    secret_subject, secret_domain = "ZQX-private-subject", "zqx-private-sender.example"
    path = tmp_path / "inbox.mbox"
    box = mailbox.mbox(path)
    for k, labels in enumerate(("Inbox,Category Updates", "Inbox,Category Promotions", "Spam")):
        box.add(_message(labels, f"{secret_subject}-{k}", f"news@{secret_domain}"))
    box.close()
    records, categories, _ = ti.load_inbox(path)
    flags = {m: np.array([1, 0, 1]) for m in ti.MODELS}
    sheet = tmp_path / "review.csv"
    assert ti.write_review(records, categories, flags, sheet) == 1  # flagged, outside Spam

    with sheet.open(newline="") as f:
        rows = list(csv.DictReader(f))
    rows[0]["my_label"] = "phish"
    with sheet.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=ti.REVIEW_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    review = ti.read_review(sheet)
    assert review == {records[0]["id"]: "phish"}

    checks = [ti.check_sender(r) for r in records]
    result = ti.aggregate(
        categories,
        flags,
        [c.verdict for c in checks],
        [list(c.warnings) for c in checks],
        {m: 0.99 for m in ti.MODELS},
        review,
        [r["id"] for r in records],
        n_bootstrap=20,
    )
    result |= {"skipped": 0, "first_month": "2026-11", "last_month": "2026-11", "cascade_shares": [1.0, 0.0]}
    result |= {"flagged_for_review": 1}
    assert result["false_alarms"]["stacked"]["all"]["flagged"] == 1
    assert result["review"]["false_alarms"]["stacked"]["flagged"] == 0  # the one I marked phishing is removed
    assert result["sender_check"]["updates"]["pass"] == 1.0
    for text in (ti.to_markdown(result), json.dumps(result)):
        assert secret_subject not in text and secret_domain not in text

    rows[0]["my_label"] = "maybe"
    with sheet.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=ti.REVIEW_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    with pytest.raises(SystemExit, match="my_label"):
        ti.read_review(sheet)
