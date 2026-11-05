from phish_triage.evaluation import own_domain
from phish_triage.features.domains import DomainRanks
from phish_triage.service.triage import own_domain_signed

RANKS = DomainRanks({"bigbank.com": 900, "tiny.com": 400_000})


def email(
    sender="alerts@mail.bigbank.com", dkim="bigbank.com", auth="spf=pass dkim=pass dmarc=pass", urls=None, extra=()
):
    return {
        "headers": [["From", f"Big Bank <{sender}>"], ["DKIM-Signature", f"v=1; d={dkim}; s=x"], *extra],
        "auth": auth,
        "auth_lower_claims_pass": False,
        "urls": ["https://www.bigbank.com/card", "https://bigbank.com/help"] if urls is None else urls,
    }


def test_signed_by_its_own_well_known_domain_with_every_link_there():
    assert own_domain_signed(email(), RANKS)


def test_each_condition_is_needed():
    assert not own_domain_signed(email(dkim="esp-mailer.net"), RANKS)  # signed by someone else
    assert not own_domain_signed(email(auth="spf=pass dkim=fail dmarc=fail"), RANKS)
    assert not own_domain_signed(email(urls=["https://www.bigbank.com/card", "https://track.esp.net/x"]), RANKS)
    assert not own_domain_signed(email(urls=[]), RANKS)  # no links at all
    assert not own_domain_signed(email(sender="news@tiny.com", dkim="tiny.com", urls=["https://tiny.com/a"]), RANKS)
    assert not own_domain_signed(email(extra=(["Reply-To", "help@elsewhere.example"],)), RANKS)  # a warning


def test_report_table():
    row = {"emails": 10, "flagged": 4, "to_review": 1}
    result = {s: {"bundle": "b", **dict.fromkeys(own_domain.ROWS, row)} for s in own_domain.SETUPS}
    text = own_domain.to_markdown(result)
    assert "| My inbox's test senders | 10 | 4, 1 | 4, 1 |" in text
