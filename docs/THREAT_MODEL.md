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
| 1 | **The service never opens, fetches or resolves URLs found in emails.** No link previews, no redirects followed, no DNS lookups of email domains. Features are computed from the URL string alone and from offline lists. | Visiting phishing/malware sites; server-side request forgery (SSRF); tipping off the attacker that the email was scanned. | No HTTP client in the feature path; Lambda has no route to fetch arbitrary URLs except the LLM endpoint (*planned, Phase 5*); a unit test asserts the parser makes no network calls (*planned, Phase 2*). |
| 2 | **Email text is always data, never instructions.** The email goes to the LLM inside clearly delimited data tags. The LLM has **no tools** and can take **no actions**. | Indirect prompt injection. | Prompt template and request builder (*planned, Phase 4*). |
| 3 | **The LLM can raise risk, never lower it.** If the classifier says phish and the LLM says safe, the result is "needs human review", never "safe". | Injection that flips the verdict to safe. | Code after the LLM call, plus the injection test set in the CI gate (*planned, Phase 4*). |
| 4 | **Every piece of evidence the LLM cites must quote the email exactly.** Every cited URL must be one the extractor found. Ungrounded indicators are dropped and counted. | Hallucinated or attacker-planted "evidence" misleading the analyst. | Grounding check, plus a CI gate on the grounding-failure rate (*planned, Phase 4*). |
| 5 | **Hidden HTML content is stripped before the LLM sees it** (comments, `display:none`, zero-size or same-colour text), and its presence is itself a signal. | Injection hidden from the human but visible to the model. | HTML normalizer (*planned, Phase 2/4*). |
| 6 | **The LLM output must match a fixed JSON schema;** anything else is rejected. | Free-text output carrying injected content into the UI. | Pydantic validation, plus a CI gate on the schema-valid rate (*planned, Phase 4*). |
| 7 | **Personal data is removed before email text leaves our AWS account.** Emails, phone numbers, one-time codes and account-like numbers are masked before the LLM call. | Sending other people's personal data to a third party. | PII redaction step, with tests (*planned, Phase 4*). |
| 8 | **Raw emails are deleted after 30 days;** verdicts and feedback are kept without bodies. For users other than the maintainer, **only verdicts and feedback are stored, never bodies**, unless they consent. | Data retention and privacy. | S3 lifecycle rule and DynamoDB schema (*planned, Phase 5/6*). |
| 9 | **Raw datasets are never committed.** Scripts download them, with checksums. | Republishing other people's email; licence violations. | `.gitignore`, a pre-commit hook and a CI check (`scripts/check_no_raw_data.py`) — **in place**. |
| 10 | **No secrets in the repo.** AWS access from CI uses OIDC (no stored keys); runtime secrets live in SSM Parameter Store. | Leaked credentials. | `detect-private-key` pre-commit hook — **in place**; OIDC and SSM (*planned, Phase 5*). |
| 11 | **Hard limits on input and spend:** 2 MB input cap, per-key rate limit, reserved concurrency on every Lambda, a code-level LLM spend cap, an AWS budget alarm and a monthly limit at the LLM provider. | Abuse, denial of service, runaway cost. | AWS budgets and the LLM provider's monthly limit — **in place**; the rest is *planned, Phase 5*. |
| 12 | **Feedback never trains a model directly.** Only feedback confirmed by the maintainer enters retraining; every retrained model must pass the same eval gate and goes out through a canary with automatic rollback. | Feedback poisoning; bad releases. | Retraining workflow and canary (*planned, Phase 6*). |
| 13 | **API keys are stored hashed,** and each key is rate-limited separately. | Key theft from the database; one key exhausting capacity. | DynamoDB keys table (*planned, Phase 5*). |
| 14 | **Sender authentication (SPF, DKIM, DMARC) is read only from the `Authentication-Results` header added by the receiving provider** (the topmost one, matching that provider's server ID). Copies added by the sender are ignored, and their presence is itself a signal. The service does not repeat these checks with its own DNS lookups (see rule 1). | Forged "pass" results; spoofed senders. | Header parser, with tests on hand-made spoofed emails (*planned, Phase 2*). |

## Known limits (accepted risks)

These are risks I can't remove completely. For each one I say what reduces it and how I measure it.

| Limit | Why it can't be fully fixed | What reduces it, and how I measure it |
|---|---|---|
| **The data doesn't look like any one person's or company's inbox.** | Public phishing comes from a few collection inboxes, and public legitimate mail is mostly mailing-list discussion, not the bank, shop and job mail that phishing imitates. | I report results per source and per time period, never one blended number. A separate test inbox of real newsletters, shop and job emails (test only, never committed) measures the false-alarm rate on realistic mail. |
| **Phishers adapt, so any fixed model gets worse over time.** | New campaigns, brands and tricks appear every month. | The time-split test measures how fast detection ages. A weekly drift check raises an alarm, and confirmed feedback feeds retraining through the eval gate and a canary rollout. |
| **"Sender verified" does not mean "safe".** | Phishers register their own look-alike domains and set up SPF and DKIM on them, so their mail passes authentication. | Sender checks are combined with look-alike-domain, display-name and link signals, never used alone. I measure how much detection depends on authentication signals by removing them and re-testing. |
| **The LLM step can still be wrong, in the direction of extra caution.** | The LLM may raise risk on a safe email. It is never allowed to lower risk. | An extra human review is cheaper than a missed phish. I measure how often the LLM step raises risk on legitimate mail. |
| **The LLM provider sees part of the email.** | The hardest cases are sent to a third-party API. | Personal data is masked first, only the hardest few percent of emails are sent, and I report that share. |
| **Header signals are only as trustworthy as the receiving provider.** | Everything above the provider's first hop can be forged. | Only the provider's own headers are trusted (rules 1 and 14). Text-only emails, which have no headers, get a separate "missing" value instead of a guess. |
| **Mostly English.** | The public datasets are mostly English. | I report this; I don't claim results for other languages. |
| **Few real users.** | This is a portfolio project, used by me and a small group of invited people. | I report real-use numbers exactly as they are, however small. |
