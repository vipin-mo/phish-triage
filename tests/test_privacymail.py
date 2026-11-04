import zipfile

import pytest

from phish_triage.data import privacymail as pm


def _eml(to: str, body: str, date: str = "Mon, 2 Mar 2020 10:00:00 +0000") -> bytes:
    return (
        f"From: News <news@shop.example>\nTo: {to}\nSubject: Offers\nDate: {date}\n"
        "DKIM-Signature: v=1; d=shop.example; s=k\nContent-Type: text/plain\n\n" + body
    ).encode()


def test_counts_read_the_zip_in_place_and_print_no_content(tmp_path):
    english = "Thanks for being with us, and here are the offers for your account from our team this week."
    german = "Vielen Dank, die neuen Angebote sind für Sie und Ihr Konto mit der Post nicht auf eine Woche."
    path = tmp_path / "newsletters.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("shop.example/id1/1.eml", _eml("a1@collect.example", english))
        z.writestr("shop.example/id1/2.eml", _eml("a1@collect.example", english, "Tue, 5 Jan 2021 09:00:00 +0000"))
        z.writestr("other.example/id2/1.eml", _eml("b2@collect.example", german))
        z.writestr("other.example/id2/notes.txt", "not an email")
    result = pm.count(path, sample=10)
    assert result["emails"] == 3 and result["websites"] == 2
    assert result["years"] == {"2020": 2, "2021": 1}
    assert result["header_share"]["DKIM-Signature"] == 1.0
    assert result["top_recipient_domains"] == [("collect.example", 3)]
    assert result["languages_in_sample"] == {"en": 2, "de": 1}
    text = repr(result)
    assert "Offers" not in text and "Thanks" not in text and "news@" not in text


def test_selection_keeps_english_drops_duplicates_and_caps_each_website(tmp_path, monkeypatch):
    from phish_triage.evaluation import privacymail as ev

    english = "Thanks for being with us, and here are the offers for your account from our team this week."
    german = "Vielen Dank, die neuen Angebote sind für Sie und Ihr Konto mit der Post nicht auf eine Woche."
    path = tmp_path / "newsletters.zip"
    with zipfile.ZipFile(path, "w") as z:
        for k in range(6):  # one website, five different English issues and one German
            body = german if k == 5 else f"{english} Issue topic {'abcdefgh'[k]}."
            z.writestr(f"shop.example/id{k}/1.eml", _eml(f"a{k}@collect.example", body))
        z.writestr("shop.example/id9/1.eml", _eml("a9@collect.example", f"{english} Issue topic a."))  # a copy
    monkeypatch.setattr(ev, "MAX_READS_PER_WEBSITE", 50)
    records, counts = ev.select(path, per_website=3)
    assert len(records) == 3 and counts["websites"] == 1
    assert all(r["source"] == "privacymail" and r["label"] == "legit" for r in records)
    assert all("collect.example" not in str(r["headers"]) for r in records)  # recipients masked
    everything, counts = ev.select(path, per_website=25)
    assert len(everything) == 5 and counts["not English"] == 1 and counts["duplicate"] == 1


def test_privacymail_emails_are_never_sent_to_an_llm():
    from phish_triage.models.llm_classifier import render_email

    with pytest.raises(PermissionError):
        render_email({"source": "privacymail", "headers": [], "subject": "x", "text": "y"})


def test_the_newsletter_split_keeps_test_websites_out_of_training():
    sizes = {site: 30 if site == "a" else 12 for site in "abcdefghij"}
    records = [{"id": f"{site}-{k}", "website": site} for site, n in sizes.items() for k in range(n)]
    base = {"train": ["p1"], "val": ["p2"], "test": ["p3"]}
    split, slices = pm.build_split(records, base)
    sites = {part: {r["website"] for r in records if r["id"] in set(split[part])} for part in split}
    assert sites["test"] and not sites["test"] & (sites["train"] | sites["val"])
    assert split["train"][0] == "p1" and split["test"][0] == "p3"  # the with_inbox split is kept as it is
    per_site = {s: sum(r["website"] == s and r["id"] in set(split["train"]) for r in records) for s in sites["train"]}
    assert max(per_site.values()) == pm.PER_WEBSITE_TRAIN
    assert set(slices["privacymail_test"]) == set(split["test"]) - {"p3"}
    assert all(len(g) == 12 and g not in sizes for g in slices["website"].values())  # names are hashed
