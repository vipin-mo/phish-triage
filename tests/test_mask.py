from phish_triage.data.mask import PLACEHOLDER_ADDRESS, auth_results, mask_record, strip_list_footer, strip_list_tag


def _record(headers, subject="Hello", text="", html="", urls=(), attachments=()):
    return {
        "id": "0" * 16,
        "source": "t",
        "label": "legit",
        "origin": "t#0",
        "date": "2024-01-01T00:00:00+00:00",
        "date_from": "received",
        "headers": [list(h) for h in headers],
        "subject": subject,
        "text": text,
        "html": html,
        "urls": list(urls),
        "attachments": list(attachments),
        "raw_bytes": 0,
        "truncated": False,
        "parse_errors": [],
    }


LIST_MAIL = [
    ("Return-Path", "<users-return-1-x=example.org@lists.example.org>"),
    ("Received", "from mx.lists.example.org by archive.ponee.io; Mon, 1 Jan 2024 00:00:00 +0000"),
    ("Delivered-To", "archive@cust-asf.ponee.io"),
    ("Mailing-List", "contact users-help@lists.example.org; run by ezmlm"),
    ("List-Id", "<users.lists.example.org>"),
    ("List-Post", "<mailto:users@lists.example.org>"),
    ("X-Spam-Score", "-0.1"),
    ("From", "Ana Lima <ana@mail.example.net>"),
    ("To", "users@lists.example.org"),
    ("Reply-To", "users@lists.example.org"),
    ("Subject", "Re: [users@lists] upgrade question"),
    ("DKIM-Signature", "v=1; a=rsa-sha256; d=mail.example.net; s=sel1; bh=abc=; b=xyz="),
]
FOOTER = (
    "---------------------------------------------------------------------\n"
    "To unsubscribe, e-mail: users-unsubscribe@lists.example.org\n"
    "For additional commands, e-mail: users-help@lists.example.org\n"
)


def test_only_sender_headers_are_kept():
    masked = mask_record(_record(LIST_MAIL, subject="Re: [users@lists] upgrade question"))
    names = [name.lower() for name, _ in masked["headers"]]
    assert names == ["from", "to", "subject", "dkim-signature"]
    assert not {"received", "delivered-to", "list-id", "x-spam-score", "return-path"} & set(names)


def test_list_artifacts_are_removed():
    masked = mask_record(_record(LIST_MAIL, subject="Re: [users@lists] upgrade question", text="Thanks!\n" + FOOTER))
    headers = dict(masked["headers"])
    assert masked["subject"] == headers["Subject"] == "Re: upgrade question"
    assert "Reply-To" not in headers  # pointed back at the list
    assert masked["text"].strip() == "Thanks!"
    assert headers["DKIM-Signature"] == "d=mail.example.net; s=sel1"


def test_reply_to_kept_when_it_is_not_the_list():
    headers = [*LIST_MAIL[:-3], ("Reply-To", "ana@mail.example.net")]
    assert "Reply-To" in dict(mask_record(_record(headers))["headers"])


def test_recipients_and_collector_identities_are_replaced_everywhere():
    headers = [("To", "Jose <jose@monkey.org>"), ("Delivered-To", "jose@login.monkey.org"), ("From", "x@evil.test")]
    masked = mask_record(
        _record(
            headers,
            subject="jose@monkey.org: your mailbox is full",
            text="Dear Jose, your monkey.org account at mail.monkey.org expires.",
            urls=["http://evil.test/login?u=jose@monkey.org"],
        )
    )
    assert dict(masked["headers"])["To"] == PLACEHOLDER_ADDRESS
    assert masked["subject"] == f"{PLACEHOLDER_ADDRESS}: your mailbox is full"
    assert masked["text"] == "Dear user, your example.com account at example.com expires."
    assert masked["urls"] == [f"http://evil.test/login?u={PLACEHOLDER_ADDRESS}"]


def test_phishing_pot_redaction_is_masked():
    masked = mask_record(_record([("To", "phishing@pot")], text="Hello phishing@pot"))
    assert masked["text"] == f"Hello {PLACEHOLDER_ADDRESS}"


def test_subject_tags_only_stripped_for_list_mail():
    assert strip_list_tag("[ANNOUNCE] Release 1.0", {"announce"}) == "Release 1.0"
    assert strip_list_tag("[Action Required] Verify now", {"users"}) == "[Action Required] Verify now"
    masked = mask_record(_record([("From", "x@evil.test")], subject="[users@lists] Verify"))
    assert masked["subject"] == "[users@lists] Verify"  # not list mail, so it stays


def test_quoted_footer_is_removed_too():
    quoted = "> " + FOOTER.replace("\n", "\n> ").rstrip("> ")
    assert strip_list_footer("Reply\n" + quoted).strip() == "Reply"


def test_auth_results_uses_topmost_header_and_drops_server_name():
    headers = [
        ("Authentication-Results", "mx.receiver.test; spf=pass smtp.mailfrom=a.test; dkim=fail header.d=a.test"),
        ("Authentication-Results", "forged.test; spf=pass; dkim=pass; dmarc=pass"),  # inserted by the sender
    ]
    assert auth_results(headers) == "spf=pass dkim=fail"
    assert auth_results([("From", "a@a.test")]) is None
    assert auth_results([("Authentication-Results", "mx.receiver.test; none")]) == "none"


def test_headers_use_one_fixed_order_and_auth_is_kept_aside():
    headers = [
        ("MIME-Version", "1.0"),
        ("Authentication-Results", "mx.receiver.test; spf=fail; dmarc=fail"),
        ("subject", "Hi"),
        ("From", "a@evil.test"),
    ]
    masked = mask_record(_record(headers))
    assert [name for name, _ in masked["headers"]] == ["From", "Subject", "MIME-Version"]
    assert masked["auth"] == "spf=fail dmarc=fail"
    assert mask_record(_record([("From", "a@evil.test")]))["auth"] is None


def test_source_names_are_replaced_everywhere_in_the_text_models_read():
    masked = mask_record(
        _record(
            [("From", "Mark <markt@apache.org>"), ("Subject", "Apache Tomcat 9")],
            subject="Apache Tomcat 9",
            text="Apache Tomcat 9 at https://tomcat.apache.org/",
            urls=["https://tomcat.apache.org/"],
        )
    )
    assert masked["text"] == "project project 9 at https://project.project.org/"
    assert masked["subject"] == dict(masked["headers"])["Subject"] == "project project 9"
    assert dict(masked["headers"])["From"] == "Mark <markt@apache.org>"
    assert masked["urls"] == ["https://tomcat.apache.org/"]


def test_html_keeps_real_domains_and_the_analyst_view_keeps_the_names():
    html = (
        '<p>Apache Tomcat 9: <a href="https://tomcat.apache.org/x">tomcat.apache.org</a>, '
        "users@tomcat.apache.org, github.com/apache/tomcat</p>"
    )
    record = _record([("Subject", "Apache Tomcat 9")], subject="Apache Tomcat 9", html=html)
    masked = mask_record(record)["html"]
    assert masked.startswith("<p>project project 9: ")  # words are masked
    for kept in (
        'href="https://tomcat.apache.org/x"',
        ">tomcat.apache.org<",
        "users@tomcat.apache.org",
        "github.com/apache/tomcat",
    ):
        assert kept in masked, kept  # link targets, link text, addresses and paths keep the real domain
    view = mask_record(record, source_names=False)
    assert view["html"] == html and view["subject"] == "Apache Tomcat 9"


def test_reply_to_naming_a_recipient_keeps_its_address():
    headers = [
        ("From", "Ann <ann@apache.org>"),
        ("To", "announce@apache.org, dev@airflow.apache.org"),
        ("Reply-To", "dev@airflow.apache.org"),
    ]
    masked = dict(mask_record(_record(headers))["headers"])
    assert masked["To"] == PLACEHOLDER_ADDRESS
    assert masked["Reply-To"] == "dev@airflow.apache.org"
    collector = dict(mask_record(_record([("From", "x@evil.test"), ("Reply-To", "jose@monkey.org")]))["headers"])
    assert collector["Reply-To"] == PLACEHOLDER_ADDRESS  # the collector's name and domain are still masked
