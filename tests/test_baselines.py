import numpy as np

from phish_triage.models.baselines import email_text, fit_all

PHISH = "Urgent: verify your account password now at {} or it will be suspended"
LEGIT = "Thanks, the patch for issue {} works on my build; merging it into the release branch"


def _data(n, offset=0):
    texts = [PHISH.format(i + offset) if i % 2 else LEGIT.format(i + offset) for i in range(n)]
    y = np.array([i % 2 for i in range(n)])
    features = np.column_stack([y + np.random.default_rng(offset).normal(0, 0.3, n), np.full(n, np.nan)])
    return texts, features, y


def test_every_baseline_fits_and_scores():
    fitted = fit_all(*_data(80), *_data(40, offset=1000))
    texts, features, y = _data(20, offset=5000)
    scores = fitted.scores(texts, features)
    assert set(scores) == {"course", "text", "features", "stacked", "text_calibrated", "stacked_calibrated"}
    for name, s in scores.items():
        assert s.shape == (20,) and ((s >= 0) & (s <= 1)).all(), name
        assert s[y == 1].mean() > s[y == 0].mean(), name


def test_email_text_uses_subject_and_body():
    assert email_text({"subject": "Hi", "text": "Body"}) == "Hi\nBody"
    assert email_text({"subject": None, "text": None}) == "\n"


def test_calibrated_ties_are_broken_by_the_raw_score():
    from phish_triage.models.baselines import _break_ties

    out = _break_ties(np.array([1.0, 1.0, 0.5]), np.array([0.9, 0.99, 0.6]))
    assert out[1] > out[0] and abs(out - [1.0, 1.0, 0.5]).max() < 1e-6 and out.max() <= 1.0


def test_models_read_the_visible_html_text_without_dates():
    from phish_triage.models.baselines import email_text

    record = {
        "subject": "Your November 2026 statement",
        "text": "Nothing to see here.",
        "html": '<p>Verify your account now with the link below</p><div style="display:none">filler words</div>',
    }
    assert email_text(record).split() == [
        "Your",
        "statement",
        "Verify",
        "your",
        "account",
        "now",
        "with",
        "the",
        "link",
        "below",
    ]
    image_only = {"subject": "Hi", "text": "plain text part", "html": '<img src="cid:x">'}
    assert email_text(image_only) == "Hi\nplain text part"  # the HTML shows nothing, so the plain part is read

    # The masked HTML keeps the source's names in links for the link features; the text models must not see them.
    listed = {"subject": "Release", "text": "", "html": "<p>Docs are at https://tomcat.apache.org/ for everyone</p>"}
    assert "apache" not in email_text(listed) and "tomcat" not in email_text(listed)


def test_emails_with_images_but_almost_no_text_go_to_review():
    from phish_triage.service.triage import too_little_text

    assert too_little_text({"text": "", "html": '<a href="https://x.test"><img src="cid:qr"></a>', "attachments": []})
    assert too_little_text({"text": "see attached", "html": "", "attachments": [{"filename": "invoice.pdf"}]})
    assert not too_little_text({"text": "short note", "html": "", "attachments": []})
    long = " ".join(["word"] * 30)
    assert not too_little_text({"text": "", "html": f"<p>{long}</p><img src=x>", "attachments": []})
