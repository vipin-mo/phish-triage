from phish_triage.data import attacks
from phish_triage.evaluation import defence
from phish_triage.evaluation import robustness as rb

PHISH_HTML = (
    "<html><body><p>Your account is locked. Verify your password at https://bad.example/login now.</p></body></html>"
)


def record(email_id, label, source, text="", html=""):
    return {
        "id": email_id,
        "label": label,
        "source": source,
        "subject": "Account notice",
        "headers": [["From", "a@b.example"], ["Subject", "Account notice"]],
        "text": text,
        "html": html,
        "urls": [],
    }


def test_copies_are_of_training_phishing_only_with_apache_filler_never_the_test_paragraph():
    legit = "Thanks for the patch. I ran the build again on the release branch and every module passed. " * 3
    records = {
        "p1": record("p1", "phish", "nazario", text="Verify your password now", html=PHISH_HTML),
        "p2": record("p2", "phish", "phishing_pot", text="Your mailbox is full, click to upgrade today"),
        "l1": record("l1", "legit", "apache", text=legit),
        "l2": record("l2", "legit", "privacymail", text="a private newsletter that must not become filler " * 10),
    }
    base = {"train": ["p1", "p2", "l1", "l2"], "val": [], "test": []}
    copies = attacks.build_copies(base, records, seed=1)
    assert [c["attacked_from"] for c in copies] == ["p1", "p2"] and all(c["label"] == "phish" for c in copies)
    assert all(c["attacked"] in attacks.TRAIN_ATTACKS and c["id"] not in records for c in copies)
    assert copies == attacks.build_copies(base, records, seed=1)
    for name in attacks.TRAIN_ATTACKS:
        c = attacks.attacked_copy(records["p1"], name, "filler words from apache mail " * 60)
        assert rb.HARMLESS[:30] not in (c.get("html") or "") and "private newsletter" not in (c.get("html") or "")
        if name.startswith("hidden_html") or name == "all_four":
            assert "filler words from apache mail" in c["html"]


def test_filler_is_300_to_400_words():
    import random

    words = len(attacks.filler(random.Random(0), ["one two three four five"]).split())
    assert attacks.FILLER_WORDS[0] <= words <= attacks.FILLER_WORDS[1]


def test_report_tables():
    counts = {"emails": 10, "flagged": 9}
    setup = {
        "clean": dict.fromkeys(defence.CLEAN_ROWS, counts),
        "attacks": dict.fromkeys([*[a for a in rb.ATTACKS if a != "clean"], *rb.HELD_OUT, "greco_llm_phish"], counts),
    }
    text = defence.to_markdown({"setups": {"deployed": setup, "c_both": setup}})
    assert "| Deployed | (c) + DistilBERT retrained |" in text
    assert "| My inbox's test senders flagged | 9 of 10 | 9 of 10 |" in text
    assert "| Held out: tinyurl links | 90.0% | 90.0% |" in text
    assert text.index("Held-out attacks") < text.index("Held out: tinyurl links")
