# Data card

What data this project uses, where it comes from, under which license, and what I do to it before any
model sees it. Raw data is never committed: `make data` downloads every source and checks it against
pinned SHA-256 checksums, and a pre-commit hook plus a CI check block raw email files from the repo.

## Why the data is built this way

My course project used one combined CSV. Its legitimate emails were mostly old (Enron, 2001) and its
phishing emails were newer, so a model could score about 98% by recognising the source rather than
phishing: the explanations showed words like `enron`, `vince` and `2004` driving the decisions.

To avoid that, this project uses:

- **raw emails with full headers** for both classes, so header and link signals can be measured;
- **both classes from the same years** (2015–2026), with each email dated by its earliest `Received:`
  hop, because the `Date:` header is written by the sender and phishers forge it;
- **more than one source per class**, so I can test on a source the model never saw in training.

## Sources

| Source | Class | Years | Format | License | Used for |
|---|---|---|---|---|---|
| [Nazario phishing corpus](https://monkey.org/~jose/phishing/) | phishing | 2004–2025 | mbox, full headers | CC-BY-4.0 | Main pool (2015–2025); older years (2004–2014) for the time test |
| [phishing_pot](https://github.com/rf-peixoto/phishing_pot) (commit `80a486701223`) | phishing | about 2022–2026 | `.eml`, full headers | CC BY-NC 4.0 (non-commercial) | Cross-source and newest-phishing tests |
| [Apache mailing-list archives](https://lists.apache.org/) (5 lists, every month 2015-01 to 2026-09) | legitimate | 2015–2026 | mbox, full headers | Public archives, no explicit license | Main pool, sampled by month to match the phishing dates |
| [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/) | legitimate + spam | 2001–2002 (released 2002–2005) | Maildir, full headers | No explicit license; published for research | Old-era comparison and leakage demo only |

The Apache lists are `announce@apache.org`, `users@httpd`, `users@tomcat`, `user@cassandra` and
`dev@community`: announcements, user support and project discussion from different communities.

**Planned, not yet added:**

| Source | Why | License |
|---|---|---|
| [Champa et al., Zenodo 8339691](https://zenodo.org/records/8339691) / the Naser Alam Kaggle CSV | Reproduce the course project's number, then show what happens to it | CC-BY-4.0 / CC BY-SA 4.0 |
| [Greco et al., Kaggle](https://www.kaggle.com/datasets/francescogreco97/human-llm-generated-phishing-legitimate-emails) | LLM-written phishing, robustness test only | CC BY-NC-SA 4.0 |
| A second legitimate source (e.g. another public mailing-list archive) | Cross-source test for the legitimate class | to be checked |
| A private test inbox (a new Gmail account subscribed to newsletters, shops and job sites) | Realistic notification-style legitimate mail; test only, never committed, only counts and metrics published | private |

**Not used, and why:**

- TREC 2006/2007 spam corpora are no longer distributed (they contained personal data).
- CEAS 2008 is no longer online.
- Enron has no `Received:` headers, so it can't support header signals, and it is the main source of
  the artifacts that inflated the course result.
- PhishFuzzer has no license file.

### Attribution

- Jose Nazario, phishing corpus, <https://monkey.org/~jose/phishing/> (CC-BY-4.0).
- rf-peixoto, Phishing Pot, <https://github.com/rf-peixoto/phishing_pot> (CC BY-NC 4.0).
- The Apache Software Foundation, public mailing-list archives, <https://lists.apache.org/>.
- The Apache SpamAssassin project, public corpus, <https://spamassassin.apache.org/old/publiccorpus/>.

## Unified record

Every source is parsed into the same record (`src/phish_triage/data/parse.py`):

| Field | Meaning |
|---|---|
| `id` | First 16 hex characters of the SHA-256 of the raw message |
| `source`, `label`, `origin` | Dataset, class (`phish`, `legit`, `spam`) and the file the message came from |
| `date`, `date_from` | UTC date from the earliest `Received:` hop; `date_from` says whether it came from there, from the `Date:` header, or is missing |
| `headers` | Every header, decoded, in original order |
| `subject`, `text`, `html` | Decoded subject and bodies (text is derived from the HTML when there is no plain-text part) |
| `urls` | Link targets and URLs in the visible text, as strings. They are never opened |
| `attachments` | File name, type and size only. Attachment content is never stored |

Spam is kept as its own label. It is not phishing, and I report it only as a separate "hard negative"
slice.

## Counts

Measured on 2026-10-30 by `make data`, **before de-duplication** (that step comes next and will be
reported here per source).

| Source | Class | Messages | Dated from `Received:` | Years with most mail |
|---|---|---:|---:|---|
| Nazario | phishing | 12,010 | 99.9% | 2005–2007 (5,428); 2015–2025: 3,662 |
| phishing_pot | phishing | 12,864 | 99.9% | 2023–2026 (12,648); 2026 alone: 6,235 |
| Apache (5 lists) | legitimate | 95,990 | 100% | 2015–2018 (51,753), falling to about 3,000 a year by 2025–2026 |
| SpamAssassin | legitimate | 6,951 | 97.5% (whole corpus) | 2002 |
| SpamAssassin | spam | 3,794 | | 2001–2002 |

What this shows:

- **Phishing in 2015–2026: 16,519 messages; legitimate: 95,981.** There is enough legitimate mail to
  match the phishing month by month for every year except 2026, where phishing_pot has more phishing
  (6,235) than the Apache lists have legitimate mail (2,990). The month-matched sampling has to handle
  that year explicitly.
- Nazario's `private-phishing4.mbox` turned out to cover mid-2007 to 2015 (3,534 messages, 2,834 of
  them from 2008–2014), which adds history for the time test.
- SpamAssassin's 2003 releases repeat many 2002 messages; de-duplication will remove them.
- Fewer than 0.1% of messages had a parse error (malformed headers or unknown character sets); they are
  kept, and the error is recorded on the record.

## Steps still to come (Phase 1)

1. Remove exact duplicates (hash of the normalized body) and near-duplicates (MinHash LSH at about 0.9
   similarity), within and across sources, and report how many were removed per source.
2. Mask source fingerprints: recipient addresses, the collecting servers' hostnames, `List-*` and
   `Delivered-To` headers, mailing-list footers.
3. Leakage audit: train a model to guess which source an email came from, plus "cheat" baselines on
   header order, year and recipient domain alone. Mask more and re-run until they fail.
4. Build the splits with fixed seeds: random, by source, and by time.

## Known limits

- **Legitimate mail is mailing-list mail.** It is technical discussion and announcements, not the bank,
  shop and job notifications that phishing imitates. The private test inbox exists to measure this gap.
- **Each phishing source comes from a few collection inboxes,** so it is not representative of any one
  person's or company's mail.
- **The `Authentication-Results` header looks different in every source,** so it can reveal the source
  instead of the sender's honesty. Measured share of messages with SPF/DKIM/DMARC results:

  | Source | Has results | Who wrote them |
  |---|---:|---|
  | phishing_pot | 99.7% | Microsoft 365 format (no server name) |
  | Apache | 55.0% | Apache's own mail and spam-filter servers |
  | Nazario | 19.6% | hostedemail.com (mostly recent years) |
  | SpamAssassin | 0% | (mail from before SPF/DKIM existed) |

  Sender-authentication features will be reduced to normalized values (`spf=pass`, `dkim=fail`, ...)
  with the server identity removed, and the leakage audit will test them on their own. The private test
  inbox, where every message carries Gmail's real results, is the fair test for the sender check.
- **Mostly English.**
