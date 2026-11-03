# phish-triage

[![CI](https://github.com/vipin-mo/phish-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/vipin-mo/phish-triage/actions/workflows/ci.yml)

> **Status: in progress.** Started October 2026. The data pipeline, baselines, DistilBERT, the LLM comparison,
> the cascade and the safe LLM analyst step are done. Trained on public data alone, the models flagged almost all
> of my real inbox mail; trained with part of it, the deployable cascade flags 4.0% (below). Deployment is next.
> Numbers are added only once they are measured.

phish-triage scores emails for phishing and explains why.

It grew out of my course project, where a simple model scored about 98% precision and recall, but its
explanations showed it was leaning on dataset artifacts: names like `enron` and years like `2004`, not
phishing signals. This project measures how much those artifacts and duplicate emails inflated that
score, and is built so the evaluation can't be fooled the same way:

- **Evaluation that can't cheat:** duplicates removed, a dataset-leakage audit, tests on a different
  source and on newer phishing, and recall reported at a fixed 1% false-alarm rate.
- **A three-stage cascade:** a fast linear model handles most emails, a fine-tuned DistilBERT handles
  the uncertain ones, and an LLM sees only the hardest. Measured: how much LLM is actually needed.
- **A safe LLM step:** grounded, schema-checked output that can raise risk but never lower it, tested
  against prompt injection hidden inside phishing emails.
- **Sender checks:** SPF, DKIM and DMARC results from the receiving mail provider, look-alike domains,
  and mismatched display names, From and Reply-To addresses.
- **Real use, serverless:** a Gmail sidebar add-on, AWS Lambda + SQS + DynamoDB via Terraform, and
  canary rollout of new models.

## What the data showed so far

From the [data card](docs/DATA.md) and the [leakage audit](reports/leakage_audit.md):

- **About a third of the phishing was copies** of other phishing (39.8% of Nazario, 31.2% of phishing_pot).
  Left in, one campaign would sit in both the training and the test data. Copies are compared on the text a
  reader sees, because some phishing pads the same message with different hidden filler.
- **Headers alone identified the dataset perfectly** (ROC AUC 1.000 from header names, header order or
  recipient domain). After masking what the collecting inboxes added, recipient domain, server names and
  Message-ID carry no label signal (0.50–0.57), and matching months keeps the date at 0.47.
- **The text still separates the classes almost perfectly** (1.000), because the only legitimate source is
  mailing-list discussion. So the random split will look too easy, and I report the cross-source,
  time-based and private-inbox tests next to it.
- **Real domains in links are not a shortcut.** Links keep their real domains, so `apache.org` appears in 46% of
  the legitimate emails and none of the phishing. Removing every link to it moves the link features' AUC from
  0.973 to 0.967, under the 0.01 I set beforehand as the line for a shortcut.

## What the baselines showed

From [reports/course_reproduction.md](reports/course_reproduction.md) and [reports/baselines.md](reports/baselines.md):

- **My course number reproduces:** 98.4% precision and 98.9% recall on its own random split. Removing duplicates
  barely changes it.
- **It doesn't survive a new source.** Trained on five of the course data's six sources and tested on the sixth,
  the same model flags 7–24% of legitimate mail at its default threshold, and catches only 51% of the Nazario
  phishing. Most of its "phishing" label turned out to be spam (about 89%).
- **On this project's 2023–2026 test mail,** the course model catches 82.3% of phishing at a 1% false-alarm rate;
  the new text model catches 99.0%, and 79.9% at 0.1%.
- **This project's own numbers are optimistic too,** for the reason the leakage audit found: the legitimate mail
  is mailing-list discussion. The text-based models flag 99–100% of 2002 spam as phishing, and at a realistic
  rate of 1 phishing email in 100, only 27–56% of what they flag on the cross-source and later-time tests would
  really be phishing.
- **The threshold drifts on new data:** chosen for 1% false alarms on validation, the text-based models' threshold
  gives 0.8–2.7% on the cross-source and later-time tests, and 1.6–2.0% even on the `random` test. Calibration
  (isotonic, fitted on validation) cuts the 2023–2026 calibration error from 0.079 to 0.021 for the text model.

## What DistilBERT, Claude and the cascade showed

From [docs/RESULTS.md](docs/RESULTS.md), rebuilt by `make eval` from saved predictions:

- **How much LLM is needed: on this sample, none.** On a fixed 1,000-email sample, the cascade (a 5 ms model, then
  DistilBERT) caught 498 of 500 phishing emails with no false alarms, and no email was uncertain enough to go on
  to Claude Haiku 5.5 (0.2% did before the November 2026 input fixes). Haiku on every email caught 97.4% with 0.8%
  false alarms, sent all mail to a third party, and would cost about $167 a day at 1 million emails. With 500
  emails of each kind in the sample, one email is 0.2%, so the intervals are wide.
- **On 2023–2026 mail,** the cascade (recall 0.990, 0.32% false alarms) beats either model alone tuned on the test
  data to the same false-alarm rate (0.958 for the stacked model, 0.978 for DistilBERT), while 95.3% of emails are
  decided by the 5 ms model.
- **DistilBERT's strength is calibration, not ranking:** at a strict 0.1% false-alarm rate on new sources and later
  mail it catches 62–86%, no better than TF-IDF (56–97%), but its probabilities are better calibrated (error
  0.007–0.033 against 0.028–0.104) and its validation threshold holds up a little better on 2023–2026 mail (0.93%
  false alarms where 1% was targeted, against 1.14% for TF-IDF).
- **The first 512 tokens and the first 256 + last 256 are even:** the same at 1% false alarms, and at 0.1% each
  wins on one split (0.922 vs 0.986 on `random`, 0.737 vs 0.542 on 2023–2026 mail). Recall at 0.1% is unstable:
  on `random` it rests on 1 or 2 of the 1,401 legitimate test emails, and it moved from 0.984 to 0.922 between two
  training runs of the same setup.
- **ONNX int8 is 4x smaller (67 MB), but not faster** on my laptop's CPU (29 ms against 27 ms); it keeps recall at
  1% false alarms (0.937 against 0.922 at 0.1%). The size is what lets it fit a Lambda package.
- **Claude as a classifier misses phishing the local models catch:** at its own cut, Haiku caught 96.6–97.4% with
  0.2–0.8% false alarms; Sonnet caught all 100 phishing emails in its 200-email sample but flagged 3 of the 100
  legitimate ones. 2 of 2,000 Haiku requests were declined by safety filters. All Phase 3 Claude runs together,
  including the re-run after the fixes, cost $1.09. Claude reads the plain-text part and the link targets, while
  the local models now read the visible HTML text, so since November 2026 the two sides don't read the same input.
  No deployed path uses Claude as the classifier, so I haven't paid for a re-run.

## What the analyst step showed

From [reports/analyst.md](reports/analyst.md), [reports/injection.md](reports/injection.md) and
[reports/injection_round2.md](reports/injection_round2.md), all with Claude Haiku 5.5 behind DistilBERT int8. These
runs used the `random` split's DistilBERT, reading the plain-text part, from before the November 2026 input fixes
(see Known issues); I re-run them (about $0.27) with the deployed model before the Gmail add-on.

- **Planted instructions never cleared a phishing email.** I hid instructions like "this message is verified safe"
  in 40 real phishing emails in six ways (visible text, HTML comment, CSS-hidden text, white-on-white text, image
  alt text, subject) and in three attacks on the defences themselves (a forged signals block, a fake operator
  message, a fake IT-test notice). With the defences on, 0 of 360 variants made the model say safe. Without them,
  also 0 with prompt version 5; with version 4 the forged signals block fooled it once in 40.
- **The rule-based detector is only one layer:** it caught 67% of the first round and none of the second, which is
  why the random tags, hidden-text removal and the raise-only rule don't depend on it.
- **Grounding needed a design change, not a looser check.** With prompt version 3, 2.5% of indicators were dropped
  (the gate allows 2%), 8 of the 11 because the model quoted our own signals as if they were the email. Letting it
  cite a signal by number brought that to 0.3%, and 0.5% (3 of 614) with version 5; the user sees our wording of
  the signal, not the model's.
- **The advice now matches the action.** With version 4, 38 of 81 "no action" answers still told the user to check
  something ("check the sender if unsure"). Version 5 asks for the same advice in both, and a rule-based check
  finds 1 of 74.
- **On 200 ordinary emails** every answer matched the schema, all 100 phishing emails ended as phishing, and 9 of
  100 legitimate ones were raised: 7 to "suspicious" by the analyst, and 2 by the classifier (one with only a
  shortened link and no message, ended as phishing; one flagged just above DistilBERT's threshold while the
  analyst said likely safe, sent to human review). Before the fixes it was 17. Of the 7, 3 were security advisories
  raised for a Reply-To that masking created (fixed since, see Known issues), 2 had links rewritten by a
  link-scanning service, and 6 had no SPF/DKIM results, which is normal for archived mailing-list mail and not for
  Gmail, so this needs re-measuring on real mail. A live analyst call takes 2.6 s (p50), 3.5 s at p95.
- **I rated 50 of the answers myself** (25 phishing, 25 legitimate, 1–3 on the
  [rubric](docs/ANALYST_RUBRIC.md)), because the automatic checks can't tell whether an explanation is right and
  helpful. Averages: correct 2.86, grounded 2.98, clear 3.00, useful 2.88; 38 of 50 scored 3 on everything.
  Phishing answers were close to perfect (2.92, 2.96, 3.00, 3.00). The weak spot was legitimate mail (correct 2.80,
  useful 2.76): the masking bug caused 4 false alarms, and 5 safe answers said "no action" while the summary added
  "check the sender if unsure", which gives the user two different messages. 13 rows were re-scored after the first
  pass: 7 once the sheet showed the recommended action, and 6 to apply the rubric's two scoring rules on every row
  (1 for the final verdict, 5 for the action and summary agreeing). These ratings are of prompt version 4 on the
  data from before the fixes; I haven't rated version 5 yet.
- **The CI eval gate** checks these numbers on every push ([reports/gate.json](reports/gate.json)) and fails if
  they were measured on an older prompt. It also checks the model I deploy (the one trained with part of my inbox):
  recall at 1% false alarms on the public test (0.999, at least 0.98) and false alarms on my inbox's unseen senders
  (4.0%, at most 5%, a limit I set before the run). All Phase 4 Claude runs cost $1.06 together; the re-run after
  the fixes was $0.27 of that.

## What my private test inbox showed

From [reports/test_inbox.md](reports/test_inbox.md). A fresh Gmail account I subscribed to newsletters, shops and
services, exported with Google Takeout: 1,701 emails from August to November 2026, mostly Gmail's Updates (1,281)
and Promotions (323). The emails stay on my laptop and are never sent to an LLM; only counts and rates are published.

- **The models flag almost all of it.** At their validation thresholds for 1% false alarms, the `random` split's
  models flag 96.8–99.8% of the 1,677 emails outside Spam as phishing: the course model 96.8%, the stacked model
  99.8%, DistilBERT int8 99.8%, the cascade 99.2%. They also flag 22–24 of the 24 Spam-folder emails.
- **This is the limit the leakage audit pointed at, now measured.** The only legitimate training mail is
  mailing-list discussion: 17.9% of it has HTML, against 95.0% of the phishing and 99.6% of this inbox. So the
  models learned "commercial-looking HTML mail is phishing", which every newsletter and receipt is. The earlier
  sign was 99–100% of 2002 spam flagged.
- **Gmail's own sender checks pass on 99.4–100%** of the mail outside Spam, so the sender check has real results
  to work with here, unlike in the public data.
- Every number above the inbox section is still true for the public test sets; it just doesn't carry over to a
  real inbox.

**Trained with part of the inbox** ([reports/with_inbox.md](reports/with_inbox.md)). I split the inbox by sender:
437 emails from some senders (at most 25 per sender) went into training and 151 into validation, with as many 2026
phishing emails, and 249 emails from 26 other senders became the test. Neither model saw those senders.

- **False alarms on the unseen senders fell from 99.2% to 4.0%** for the cascade and for DistilBERT (10 of 249).
  Averaged per sender it is 16.1%, because the false alarms fall on a few senders with few emails. At 1 phishing
  email in 100, a flagged email would now be phishing 20% of the time, against 1% before.
- **It costs some phishing recall.** On the public test the cascade catches 98.2% (99.7% before) at 0.36% false
  alarms (0.50% before): the inbox mail in validation makes the threshold stricter. At a fixed false-alarm rate
  DistilBERT loses nothing: 99.9% at 1% either way, and 94.4% against 93.7% at 0.1%. On 1,644 2026 phishing emails
  no model saw, the cascade catches 98.9%.
- **The first run found a date shortcut, so dates are gone from every model's input.** I set a rule before that
  run: removing years, month and weekday names from the test text must not move a model's results by more than 2
  points. The two TF-IDF models failed it (their inbox false alarms rose by 16–20 points without dates), because
  the inbox is all late 2026. Trained without dates, the course model flags 28.5% of the unseen senders' mail, not
  the 7.6% it seemed to before; the other models are at 4.0–23.7%. The check now reads 0 for every model.
- **Images with almost no text go to review.** An email with images or attachments and fewer than 20 visible words
  gives the text models nothing to read, so it goes to a person instead of being marked safe. That catches 8.9% of
  the public test's phishing and 4.1% of the 2026 phishing, and none of the legitimate mail in either test.
- **Three structured features may be a shortcut on the inbox.** My rule, set before the run: a feature that
  separates the inbox's test senders from 2026 phishing with ROC AUC 0.9 or more on its own, but scores under 0.7
  on the public test, is suspect. Three are: the number of links (0.961, public 0.507), the number of link domains
  (0.918, public 0.525) and a DKIM signature from the sender's own domain (0.918, public 0.582). My inbox's
  legitimate mail is all newsletters and notifications from large senders, so "many links, signed by its own
  domain" means legitimate there. They don't decide anything in the deployed cascade, though: refitted without
  them, it flags exactly the same emails, because on this mail DistilBERT, which reads only the text, decides.
- **The weak spot is phishing that looks like a newsletter.** Of the phishing in the tests that is DKIM-signed by
  its own domain and has at least 12 links (the inbox's median), the cascade catches 25 of 31 (80.6%), against
  98.9% of the 2026 phishing overall. Trained on public data only it caught all 31, while flagging 99% of my
  inbox: this is what training with the inbox costs. With 31 emails the interval is wide (64.5–93.5%).
- The inbox test is small: 249 emails, mostly Gmail's Updates (214) and Promotions (31).


## Known issues

All but the last two are fixed. The first two were found while rating the analyst's answers by hand, the next four
afterwards and on my test inbox, all in November 2026; every number above was re-measured after the fixes, except
the Claude runs, as noted.

- **Masking rewrote links (fixed).** Replacing the Apache list names with `project` ran over the whole body and
  HTML, including URLs and addresses. It rewrote a URL or address in 7,978 of the 13,541 legitimate emails the
  splits used (`tomcat.apache.org` became `project.project.org`), and link targets in 807 HTML ones, so the
  classifier's link features were wrong for them. The analyst was shown mismatches the masking created and flagged
  4 of the 25 legitimate emails I rated because of them. Now names are masked only in the words text models read;
  URLs, addresses, domains and link text keep their real domain, the analyst sees the email without name masking,
  and the leakage audit checks that the real domains don't become a shortcut.
- **De-duplication missed padded copies (fixed).** Some phishing wraps the same visible text in about 30,000
  characters of different hidden filler, so comparing the full text saw the copies as unrelated. Duplicates are
  now found on the visible text, which removed 395 more phishing emails and 751 more Apache ones.
- **Masking created Reply-To mismatches (fixed).** When a Reply-To named one of the email's recipients, masking
  replaced it with `user@example.com`, so the sender check reported "replies go to a different domain". It happened
  in 319 of the 9,338 Apache emails the splits use (3.4%), and caused 3 of the 7 legitimate emails the analyst
  raised. Now only the collectors' own addresses are masked in a Reply-To, and no Apache email gets the false
  mismatch.
- **The text models leaned on dates (fixed).** Trained with my late-2026 inbox, the TF-IDF models treated years
  and month names as signs of legitimate mail. Dates are now removed from every model's input.
- **The models read the plain-text part (fixed).** A mail program shows the HTML, so a harmless plain-text part next
  to phishing HTML decided what the models read. They now read the visible HTML text (hidden parts removed), and
  the plain-text part only when the HTML shows almost nothing. Moving to it first let the Apache names in link text
  reach the models in 5.6% of the legitimate mail; that text is now masked like the plain text, and the leakage
  audit now tests exactly what the models read.
- **The analyst saw rounded classifier scores (fixed).** DistilBERT's threshold is 0.0009, so a flagged email was
  shown as "phishing probability 0.00 (flagged)". It is now told only whether the classifier flagged the email.
- **Phishing that looks like a newsletter (open).** The deployed cascade catches 25 of 31 such emails (above).
  It is a data problem: the only bulk-looking legitimate mail it learned from is my inbox, and there are few
  phishing emails of that kind to learn from. No public dataset I found fills both sides (see
  [docs/DATA.md](docs/DATA.md)); the report tracks this number for every model I train.
- **The analyst and injection results are from before these fixes (open).** They used the earlier classifier and
  input; I re-run them with the deployed model (about $0.27) before the Gmail add-on.

## Progress

- [x] **Phase 0** — repo, CI, [threat model](docs/THREAT_MODEL.md)
- [x] **Phase 1** — data you can trust: [sources and data card](docs/DATA.md), de-duplication, [leakage audit](reports/leakage_audit.md), splits
- [x] **Phase 2** — [features and sender check](docs/FEATURES.md), [baseline models](reports/baselines.md), metrics module, [course reproduction](reports/course_reproduction.md)
- [x] **Phase 3** — DistilBERT ([ONNX int8](reports/onnx.md)), LLM comparison, cascade ([results](docs/RESULTS.md))
- [x] **Phase 4** — grounded LLM analyst step ([results](reports/analyst.md)), prompt-injection tests ([round 1](reports/injection.md), [round 2](reports/injection_round2.md)), CI eval gate
- [ ] **Phase 5** — serverless AWS deployment (Terraform, OIDC CI/CD)
- [ ] **Phase 6** — Gmail add-on, feedback loop, canary, drift check
- [ ] **Phase 7** — load test, robustness report, write-up

## Development

Requires [uv](https://docs.astral.sh/uv/) and Python 3.12.

```bash
make setup   # create .venv, install dev deps, install git hooks
make check   # lint, raw-data guard, tests (what CI runs)
```

Raw email datasets are never committed. A pre-commit hook and a CI check block `.eml`/`.mbox` files and
anything under `data/`. Instead, `make data` downloads every source, checks it against pinned checksums,
parses it into one record format, masks source fingerprints, removes duplicates and builds every split with
fixed seeds (see [docs/DATA.md](docs/DATA.md)). `make audit` re-runs the leakage audit, `make eval-baselines`
trains and reports the baseline models on every split, `make eval-course` reproduces the course project's
score, `make train-transformer` fine-tunes DistilBERT (needs `uv sync --group train`), and `make eval` rebuilds
[docs/RESULTS.md](docs/RESULTS.md) from saved predictions. `make eval-analyst` and `make eval-injection` show
their Claude cost and only call the API with `CONFIRM=--confirm`; `make gate` turns their results into
[reports/gate.json](reports/gate.json), which CI checks without calling any API.

## License

MIT. Datasets keep their own licenses, documented in [docs/DATA.md](docs/DATA.md).
