# Threat model

I wrote this before any code that touches email, and I update it when the design changes. Each rule in
[Design rules](#design-rules) is enforced in code or infrastructure and covered by a test or a CI check.
The "Enforced by" column says where; entries marked *planned* name the phase that adds it.

## What the system does

phish-triage receives one email (raw `.eml` or plain text) and returns a verdict (`phish`,
`suspicious`, `likely_safe`), a risk score and the signals behind it. A three-stage cascade decides
how much work each email gets:

1. a fast linear model (most emails stop here);
2. a fine-tuned DistilBERT for the uncertain band;
3. an LLM that writes an analyst summary for the hardest cases only.

Users reach it from a Gmail sidebar add-on, and their feedback (`correct`, `false_alarm`,
`missed_phish`) feeds retraining. It runs on AWS Lambda, SQS, DynamoDB and S3.

## Assets (what we protect)

| Asset | Why it matters |
|---|---|
| **Users' credentials and money** | A missed phish can lead directly to account takeover or payment fraud. |
| **Analysts' attention** | Too many false alarms train people to ignore the tool. |
| **Privacy of the email content** | Emails contain names, addresses, one-time codes, account and order details, and other people's mail. |
| **Integrity of the model and training data** | Poisoned feedback or a bad model release silently weakens detection for everyone. |
| **The cloud account and its bill** | Abuse or a runaway loop can create real cost. |
| **API keys** | Keys for the scan API and the LLM provider. |

## Attackers

| Attacker | Goal | Capability |
|---|---|---|
| **Phisher (adaptive)** | Get a phishing email rated safe. | Controls the entire email: headers they can forge, body, HTML, links, attachments. Can test variants against public filters and reword with an LLM. |
| **Phisher targeting the LLM step** | Make the LLM summary say "safe" or mislead the analyst. | Puts instructions inside the email: visible text, HTML comments, hidden (white-on-white, zero-size) text, image alt text, headers. This is *indirect prompt injection*: the attacker is the content, not the user. |
| **Feedback poisoner** | Teach the model that a campaign is safe. | Has, or creates, a user account and submits false `false_alarm` feedback. |
| **API abuser** | Free compute, denial of service, or a large bill. | Can call the public endpoint with or without a stolen key, and send large or malformed inputs. |
| **Curious insider / repo reader** | Read other people's email. | Can read the public repo, logs, and anything accidentally committed. |

**Out of scope:** a compromised AWS or Google account, a compromised maintainer laptop, and attacks on
Anthropic's or Google's own infrastructure. This project does not try to defend against these.

## Trust boundaries

```
 untrusted                     │ our code                                │ third parties
───────────────────────────────┼─────────────────────────────────────────┼────────────────────
 email content (all of it)  ──►│ parser → features → stage 1 → stage 2   │
 user feedback              ──►│        │                                │
 API requests               ──►│        └─► LLM prompt (email as DATA) ─►│ Anthropic API
                               │ DynamoDB / S3 (our AWS account)         │
```

- **Everything inside an email is untrusted**, including headers. `From`, `Reply-To`, `Date` and most
  `Received` lines can be forged by the sender; only the hops added by the receiving provider are
  trustworthy, and only for that provider. A sender can even insert a fake `Authentication-Results`
  header that says `spf=pass dkim=pass`, so only the copy added by the receiving provider counts.
- **The LLM's output is also untrusted.** It is parsed, validated and checked against the email before
  anything uses it.
- **Feedback is untrusted** until it is confirmed (see the retraining rules below).

## Design rules

| # | Rule | Threat addressed | Enforced by |
|---|---|---|---|
| 1 | **The service never opens, fetches or resolves URLs found in emails.** No link previews, no redirects followed, no DNS lookups of email domains. Features are computed from the URL string alone and from offline lists. | Visiting phishing/malware sites; server-side request forgery (SSRF); tipping off the attacker that the email was scanned. | No HTTP client in the feature path, and a test scans emails with links while every network call fails (`tests/test_scanner.py`) — **in place**. The Lambda itself can reach the internet. Putting it in a VPC whose only way out is the LLM API would need a NAT gateway with an egress filter (from about $32/month for the NAT gateway alone), so for now the guarantee is in the code and its test, not the network. |
| 2 | **Email text is always data, never instructions.** The email goes to the LLM inside clearly delimited data tags. The LLM has **no tools** and can take **no actions**. | Indirect prompt injection. | `service/analyst.py`: the email sits between tags with a random id per request, so text inside it can't close the block or fake the signals; tag look-alikes are neutralized after Unicode normalization; the request has no tools. Tested in `tests/test_analyst.py`. |
| 3 | **The LLM can raise risk, never lower it.** If the classifier says phish and the LLM says safe, the result is "needs human review", never "safe". | Injection that flips the verdict to safe. | `analyst.final_verdict` (every combination tested), plus the injection rounds in `evaluation/injection.py` and the CI eval gate (verdict flip rate must be 0). |
| 4 | **Every piece of evidence the LLM cites must quote the email exactly, or name one of our own signals.** Every cited URL must be one the extractor found. Ungrounded indicators are dropped and counted. | Hallucinated or attacker-planted "evidence" misleading the analyst. | `analyst.grounded`: every quote must appear in what the model was shown, every URL must be one the email contains, and a cited signal number must exist (the user sees our wording of the signal, not the model's); failures are dropped and counted, and the CI eval gate fails above 2%. |
| 5 | **Hidden HTML content is stripped before the LLM sees it** (comments, `display:none`, zero-size or same-colour text), and its presence is itself a signal. | Injection hidden from the human but visible to the model. | `features/html.visible_html`: comments, `display:none`/`hidden`, zero-size or transparent text, low-contrast text (WCAG ratio below 1.5) and image alt text are removed; the techniques found are reported as a signal. Checked against 5,596 real HTML emails and crafted cases. |
| 6 | **The LLM output must match a fixed JSON schema;** anything else is rejected. | Free-text output carrying injected content into the UI. | `analyst.AnalystOutput` (pydantic) after a JSON-schema response; anything else is rejected and the classifier's verdict stands. The CI eval gate requires 100% schema-valid answers. |
| 7 | **Personal data is removed before email text leaves our AWS account.** Emails, phone numbers, one-time codes and account-like numbers are masked before the LLM call. | Sending other people's personal data to a third party. | `service/pii.py` (email local parts, phone, card with Luhn check, SSN, IBAN, one-time codes, account numbers), with tests. Person names are not removed (see Known limits). |
| 8 | **The service stores no email.** Only the verdict, the score and the email's SHA-256 (the scan id) are kept, with feedback; no body, subject or sender. (The plan had raw emails in S3 for 30 days; I chose not to keep them at all.) | Data retention and privacy. | `service/store.py` and the DynamoDB tables (infra/service): no field holds email content; a test checks the stored verdict has none — **in place**. |
| 9 | **Raw datasets are never committed.** Scripts download them, with checksums. | Republishing other people's email; licence violations. | `.gitignore`, a pre-commit hook and a CI check (`scripts/check_no_raw_data.py`) — **in place**. |
| 10 | **No secrets in the repo, and no stored AWS keys.** Deploys run from my laptop with a short MFA session; CI has no AWS access. (The plan was CI with OIDC, but the AWS Free plan denies creating the OIDC provider; the workflow and roles are written and switch on with one variable on an account that allows it.) Runtime secrets would live in SSM Parameter Store; there are none yet, as the LLM step is off. | Leaked credentials. | `detect-private-key` pre-commit hook; MFA-only admin role; `make deploy-*` — **in place**. |
| 11 | **Hard limits on input and spend:** 2 MB input cap, per-key rate limit, reserved concurrency on every Lambda, API Gateway throttling, a code-level LLM spend cap, an AWS budget alarm and a monthly limit at the LLM provider. | Abuse, denial of service, runaway cost. | `service/api.py` (2 MB, 60 per key per minute); infra/service (scan: at most 5 at once, explain: 1; API: 5 requests/s, bursts of 10); AWS budgets and the LLM provider's monthly limit — **in place**. |
| 12 | **Feedback never trains a model directly.** Only feedback confirmed by the maintainer enters retraining; every retrained model must pass the same eval gate and goes out through a canary with automatic rollback. | Feedback poisoning; bad releases. | Retraining workflow and canary (*planned, Phase 6*). |
| 13 | **API keys are stored hashed,** and each key is rate-limited separately. | Key theft from the database; one key exhausting capacity. | `service/store.py`, `store_dynamo.py`: SHA-256 of a random 32-byte key; the key is shown once (`make api-key`); per-key counter in DynamoDB — **in place**. |
| 14 | **Sender authentication (SPF, DKIM, DMARC) is read only from the `Authentication-Results` header added by the receiving provider** (the topmost one, matching that provider's server ID). Copies added by the sender are ignored, and their presence is itself a signal. The service does not repeat these checks with its own DNS lookups (see rule 1). | Forged "pass" results; spoofed senders. | `mask.auth_results` reads only the topmost header (tested with a forged lower copy). Matching the provider's server ID and the spoofed-email tests: *planned, Phase 2*. |

## Known limits (accepted risks)

These are risks I can't remove completely. For each one I say what reduces it and how I measure it.

| Limit | Why it can't be fully fixed | What reduces it, and how I measure it |
|---|---|---|
| **The data doesn't look like any one person's or company's inbox.** | Public phishing comes from a few collection inboxes, and public legitimate mail is mostly mailing-list discussion, not the bank, shop and job mail that phishing imitates. | I report results per source and per time period, never one blended number. A separate test inbox of real newsletters, shop and job emails (never committed, never sent to an LLM) measures the false-alarm rate on realistic mail: the first models flagged 96.8–99.8% of it; trained with part of it (split by sender), the cascade flagged 4.0% of the emails from unseen senders, but 76.5% of PrivacyMail's newsletters from 944 websites, so 26 senders were too few. Trained with part of PrivacyMail too (split by website), it flags 0.9% of newsletters from held-out websites and 2.0% of my inbox's unseen senders, and the eval gate checks both. Phishing that looks like a newsletter (signed by its own domain, many links) is the weak spot: the deployed cascade catches 23 of 31. I report it for every model as a known gap. |
| **Phishers adapt, so any fixed model gets worse over time.** | New campaigns, brands and tricks appear every month. | The time-split test measures how fast detection ages. A weekly drift check raises an alarm, and confirmed feedback feeds retraining through the eval gate and a canary rollout. |
| **"Sender verified" does not mean "safe".** | Phishers register their own look-alike domains and set up SPF and DKIM on them, so their mail passes authentication. | Sender checks are combined with look-alike-domain, display-name and link signals, never used alone. I measure how much detection depends on authentication signals by removing them and re-testing. |
| **The LLM step can still be wrong, in the direction of extra caution.** | The LLM may raise risk on a safe email. It is never allowed to lower risk. | An extra human review is cheaper than a missed phish. I measure how often the LLM step raises risk on legitimate mail: 7 of 100 legitimate emails in the analyst evaluation were raised to "suspicious" (17 before the November 2026 masking fix). 6 of the 7 had no SPF/DKIM results, as is normal for archived mailing-list mail, and 3 had a Reply-To mismatch that masking created (fixed since), so I re-measure this with the deployed model before Phase 6 and on real Gmail mail in Phase 6. |
| **The LLM provider sees part of the email.** | The hardest cases are sent to a third-party API. | Personal data is masked first, only the hardest few percent of emails are sent, and I report that share. |
| **Header signals are only as trustworthy as the receiving provider.** | Everything above the provider's first hop can be forged. | Only the provider's own headers are trusted (rules 1 and 14). Text-only emails, which have no headers, get a separate "missing" value instead of a guess. |
| **Person names reach the LLM.** | Finding names needs a named-entity model, hundreds of megabytes in the Lambda package. | Addresses, numbers and codes are masked, and only emails the classifier flags or can't decide on are sent (on its 1,000-email test sample the cascade left none undecided after the November 2026 input fixes, 0.2% before). |
| **Rule-based detection of instructions aimed at an AI is incomplete.** | Attackers can phrase instructions in endless ways. | It is one layer, not the defence: the random tags, hidden-text removal and the raise-only rule don't depend on it. I report its detection rate on the injection set as measured, without tuning it to that set. |
| **Crafted input could try to exhaust CPU or crash the parser.** | Email is attacker-controlled. | Patterns are bounded (no backtracking blow-up), HTML parsing is linear with a depth cap, deeply nested MIME becomes a recorded parse error, and tests hold each of these to a time limit (`tests/test_adversarial_inputs.py`). Input size limits come with the service (rule 11). |
| **Emails that are mostly images or attachments.** | The text models judge words; an image-only, QR-code or attachment-only email gives them almost none, and the service doesn't read images or open attachments. | An email with images or attachments and fewer than 20 visible words goes to human review instead of being marked safe (`service/triage.py`). I report the share sent there: 8.9% of the public test's phishing and 4.1% of the 2026 phishing, and no legitimate email in the public test or my inbox. |
| **Mostly English.** | The public datasets are mostly English. | I report this; I don't claim results for other languages. |
| **Few real users.** | This is a portfolio project, used by me and a small group of invited people. | I report real-use numbers exactly as they are, however small. |
