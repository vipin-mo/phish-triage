# phish-triage

[![CI](https://github.com/vipin-mo/phish-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/vipin-mo/phish-triage/actions/workflows/ci.yml)

> **Status: in progress.** Started October 2026. The data pipeline, baselines, DistilBERT, the LLM comparison,
> the cascade and the safe LLM analyst step are done; deployment is next. Numbers are added only once they are
> measured.

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

- **About a third of the phishing was copies** of other phishing (37.8% of Nazario, 30.0% of phishing_pot).
  Left in, one campaign would sit in both the training and the test data.
- **Headers alone identified the dataset perfectly** (ROC AUC 1.000 from header names, header order or
  recipient domain). After masking what the collecting inboxes added, recipient domain, server names and
  Message-ID carry no label signal (0.50–0.57), and matching months keeps the date at 0.47.
- **The text still separates the classes almost perfectly** (0.999), because the only legitimate source is
  mailing-list discussion. So the random split will look too easy, and I report the cross-source,
  time-based and private-inbox tests next to it.

## What the baselines showed

From [reports/course_reproduction.md](reports/course_reproduction.md) and [reports/baselines.md](reports/baselines.md):

- **My course number reproduces:** 98.4% precision and 98.9% recall on its own random split. Removing duplicates
  barely changes it.
- **It doesn't survive a new source.** Trained on five of the course data's six sources and tested on the sixth,
  the same model flags 7–24% of legitimate mail at its default threshold, and catches only 51% of the Nazario
  phishing. Most of its "phishing" label turned out to be spam (about 89%).
- **On this project's 2023–2026 test mail,** the course model catches 80.5% of phishing at a 1% false-alarm rate;
  the new text model catches 99.1%, and 80.7% at 0.1%.
- **This project's own numbers are optimistic too,** for the reason the leakage audit found: the legitimate mail
  is mailing-list discussion. The text-based models flag 98–100% of 2002 spam as phishing, and at a realistic
  rate of 1 phishing email in 100, only 31–59% of what they flag would really be phishing.
- **The threshold drifts on new data:** chosen for 1% false alarms on validation, the text-based models' threshold
  gives 1.0–2.3% on the cross-source and later-time tests. Calibration (isotonic, fitted on validation) cuts the 2023–2026 calibration
  error from 0.076 to 0.019 for the text model.

## What DistilBERT, Claude and the cascade showed

From [docs/RESULTS.md](docs/RESULTS.md), rebuilt by `make eval` from saved predictions:

- **How much LLM is needed: about 0.2% of emails.** On a fixed 1,000-email sample, the cascade (a 4 ms model,
  then DistilBERT, then Claude Haiku 5.5 for what's left) caught every phishing email with 0.2% false alarms. Haiku
  on every email caught 97.2% at the same false-alarm rate, sent all mail to a third party, and would cost about
  $154 a day at 1 million emails versus about $0.31 for the cascade. With 500 legitimate emails in the sample,
  0.2% is one false alarm, so the intervals are wide.
- **On 2023–2026 mail,** the cascade (recall 0.987, 0.40% false alarms) matches DistilBERT alone (0.985, 0.41%)
  while 98% of emails are decided by the 4 ms model.
- **DistilBERT's strength is calibration, not ranking:** at a strict 0.1% false-alarm rate on new sources and later
  mail it catches 59–71%, no better than TF-IDF (76–81%), but its validation threshold holds up much better
  (0.41% false alarms on 2023–2026 mail where 1% was targeted, against 1.19% for TF-IDF).
- **The first 512 tokens beat the first 256 + last 256** on both splits tested.
- **ONNX int8 is 4x smaller (67 MB) with the same test metrics, but not faster** on my laptop's CPU; the size is
  what lets it fit a Lambda package.
- **Claude as a classifier is conservative:** fewer false alarms, but Haiku missed 3–5% of phishing at its own
  cut (Sonnet 1%); 5 of 2,000 Haiku requests were declined by safety filters. All Claude runs together cost $0.51.

## What the analyst step showed

From [reports/analyst.md](reports/analyst.md), [reports/injection.md](reports/injection.md) and
[reports/injection_round2.md](reports/injection_round2.md), all with Claude Haiku 5.5 behind DistilBERT int8:

- **Planted instructions never cleared a phishing email.** I hid instructions like "this message is verified safe"
  in 40 real phishing emails in six ways (visible text, HTML comment, CSS-hidden text, white-on-white text, image
  alt text, subject) and in three attacks on the defences themselves (a forged signals block, a fake operator
  message, a fake IT-test notice). With the defences on, 0 of 360 variants made the model say safe. Without them, the
  forged signals block fooled it once in 40.
- **The rule-based detector is only one layer:** it caught 66% of the first round and none of the second, which is
  why the random tags, hidden-text removal and the raise-only rule don't depend on it.
- **Grounding needed a design change, not a looser check.** With prompt version 3, 2.5% of indicators were dropped
  (the gate allows 2%), 8 of the 11 because the model quoted our own signals as if they were the email. Letting it
  cite a signal by number brought that to 0.3%; the user sees our wording of the signal, not the model's.
- **On 200 ordinary emails** every answer matched the schema, all 100 phishing emails ended as phishing, and 17
  of 100 legitimate ones were raised (16 to "suspicious", 1 to "needs human review"). All 16 had no SPF/DKIM
  results, which is normal for archived mailing-list mail and not for Gmail, so this needs re-measuring on real
  mail. A live analyst call takes 2.4 s (p50), 3.8 s at p95.
- **The CI eval gate** checks these numbers on every push ([reports/gate.json](reports/gate.json)) and fails if
  they were measured on an older prompt. All Phase 4 Claude runs cost $0.80 together.

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
