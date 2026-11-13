# Model card

The model in service since 2026-11-12: bundle `with-visible-20261112-ac59a4e3` ([infra/bundle-version](../infra/bundle-version),
[reports/bundle.md](../reports/bundle.md)). The bundle itself is private, because it is trained partly on my test inbox
and on PrivacyMail; this page describes it.

## What it is for

It scores one email at a time for phishing, for one user (me), from a Gmail add-on. A flag means "look closer",
not "delete": if 1 email in 100 were phishing, about 0.38 of the emails it flags would be phishing. It isn't meant
to block, delete or file mail on its own, or to judge mail very different from what it was tested on (see Limits).

## How it decides

1. **Stage 1, a stacked model:** gradient-boosted trees (scikit-learn `HistGradientBoostingClassifier`) on 42
   structured features (header, link, HTML, attachment and text signals; [docs/FEATURES.md](FEATURES.md)) plus the
   score of a calibrated TF-IDF and logistic-regression text model. It decides an email when it is sure: below
   0.00459 safe, above 0.9968 phishing. In the tests it decides 92–93% of the public and 2026 test emails, 81% of
   the held-out newsletters and 40% of my test inbox.
2. **Stage 2, DistilBERT** (`distilbert-base-uncased`, fine-tuned for 2 epochs on the first 512 tokens, served as
   ONNX fp32 because int8 scores change with the batch): everything stage 1 isn't sure of. It flags above 0.9737,
   the threshold for 1% false alarms on validation.
3. **Rules around them:** an unflagged email with images or attachments and fewer than 20 visible words goes to
   review. The sender check (SPF, DKIM, DMARC, look-alike domains, display names) is shown next to the verdict and
   doesn't change it. Stage 1 also has header features (the sender's domain, display name, Reply-To, DKIM), but
   refitted without them it catches and flags the same emails, bar 2 of 1,644
   ([reports/sender_ablation.md](../reports/sender_ablation.md)).

Both stages read the email with reader 3 ([docs/FEATURES.md](FEATURES.md), the robustness defence in
[reports/defence.md](../reports/defence.md)): the visible HTML text with `<style>` rules, off-screen and tiny text
applied, text pushed away with `text-indent`, `clip` or `transform` hidden, text imitating the analyst's signals
block dropped, invisible characters removed and look-alike letters in mixed-script words turned back into Latin.
Stage 1 was fitted on reader-3 text; DistilBERT is the one fine-tuned on reader-2 text, which is the same text on
every test email (a DistilBERT retrained on reader 3 did worse on my test inbox, docs/FINDINGS.md). Every threshold
and cutoff was chosen on the validation split.

Claude Haiku 5.5 explains a verdict when I ask (`POST /v1/explain`). It can raise a verdict, never lower it, and
isn't part of the scan.

## Training data

The `with_visible` split ([docs/DATA.md](DATA.md)): 18,745 training, 4,699 validation and 8,433 test emails.

- **Public:** phishing from the Nazario corpus and phishing_pot, legitimate mail from five Apache mailing lists,
  month-matched from 2015 to 2026, de-duplicated and masked (collection inboxes, list names).
- **Private, never published:** part of my test inbox (a Gmail account I subscribed to newsletters and shops),
  split by sender; part of PrivacyMail's newsletters, split by website; 2026 phishing in all three parts; and the
  21 emails I sent for retraining from the add-on (all legitimate; stage 1 only).

## How well it works

On test emails it never trained on ([README](../README.md#results), with Wilson 95% intervals):

| Test | Result |
|---|---|
| Public test phishing (1,401) | 97.8% caught (96.9–98.4%) |
| Public test legitimate mail (1,401) | 0.2% flagged (0.1–0.6%) |
| 2026 phishing, same source and months as training (1,644) | 98.3% caught (97.5–98.8%) |
| Phishing that looks like a newsletter (31) | 74% caught (57–86%) |
| My test inbox, 26 senders held out of training (249) | 1.6% flagged (0.6–4.1%) |
| Later mail from the held-out inbox senders, no model chosen on it (154) | 3.9% flagged (1.8–8.2%) |
| Newsletters from 189 websites held out of training (3,738) | 1.3% flagged (1.0–1.7%), 2.2% with review |
| LLM-written phishing (1,000) | 94.0% caught (92.4–95.3%) |
| Phishing three months newer than training (354; a candidate trained on phishing up to July 2026) | 83.1% caught (78.8–86.6%) |

These sets were scored for every model I compared and the one in service was chosen on them, so they are closer to
validation numbers than to a fresh test; the later inbox mail ([reports/fresh_inbox.md](../reports/fresh_inbox.md))
is the exception. The legitimate labels are Gmail's folder and the dataset's, not a hand check.
Two of the 26 inbox test senders share a domain with training (docs/DATA.md). Its robustness to evasion tricks is in
[reports/defence.md](../reports/defence.md) (setup d, the same models).

## Limits

- One public legitimate source, mailing-list discussion; two phishing sources; one person's test inbox and real
  mail, mostly bulk mail.
- Newsletter-like phishing is its weak spot (23 of 31), and genuine notices from big brands asking me to act can
  read as phishing ([Known issues](FINDINGS.md#known-issues)).
- Hidden text is caught trick by trick: 97.8% under `text-indent`, `clip` and `transform`, which reader 3 has rules
  for (6.9% with reader 2), but 7.3% under six new tricks held out since 2026-11-13, which it has none for.
- On my real mail it flags more than the tests show: 10 of the 14 emails the previous model flagged were false
  alarms I marked, all decided by DistilBERT, which this model didn't retrain.
- It ages within months: trained on phishing up to July 2026, a candidate caught 98.2% of August's phishing,
  95.5% of September's and 83.1% of October's ([reports/time_split.md](../reports/time_split.md)). Keeping up
  needs new public phishing and a full retrain; `make retrain` with the emails I send refits stage 1 only.
- It doesn't read images or QR codes.
- Only English newsletters were taken from PrivacyMail; other languages weren't measured on their own.

## Privacy and licences

The service stores no email, only a verdict, a score and the email's SHA-256, unless I send one for retraining
([THREAT_MODEL.md](THREAT_MODEL.md)). The weights aren't published: the text models' vocabulary comes partly from
private mail. The code is MIT-licensed; the data the model is trained on includes phishing_pot (CC BY-NC 4.0), so
the model and its results are for non-commercial use.

## How it changes

A new model is trained from my laptop (`make retrain`, which adds the emails I sent to this split and refits stage
1, or a new split), must reproduce its report one email at a time
(`make bundle`), pass the eval gate (`make gate`), and goes out through a canary: a smoke check that also fails a
version whose loaded model isn't the pinned bundle, then 10% of traffic for 10 minutes, rolled back on the alarms. A
deliberate deployment of the previous version was stopped by that check before any traffic moved
([reports/canary_rollback.md](../reports/canary_rollback.md)). A weekly drift check compares the week's verdicts
with this model's on held-out legitimate mail.
