# Data card

What data this project uses, where it comes from, under which license, and what I do to it before any
model sees it. Raw data is never committed: `make data` downloads every source, checks it against pinned
SHA-256 checksums, and builds the masked, de-duplicated splits. A pre-commit hook plus a CI check block raw
email files from the repo.

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
| [Nazario phishing corpus](https://monkey.org/~jose/phishing/) | phishing | 2004–2025 | mbox, full headers | CC-BY-4.0 | Main pool (2015–2025); older years (2004–2014) for the old-era comparison |
| [phishing_pot](https://github.com/rf-peixoto/phishing_pot) (commit `80a486701223`) | phishing | about 2022–2026 | `.eml`, full headers | CC BY-NC 4.0 (non-commercial) | Main pool; cross-source and newest-phishing tests |
| [Apache mailing-list archives](https://lists.apache.org/) (5 lists, every month 2015-01 to 2026-09) | legitimate | 2015–2026 | mbox, full headers | Public archives, no explicit license | Main pool, sampled by month to match the phishing dates |
| [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/) | legitimate + spam | 2001–2002 (released 2002–2005) | Maildir, full headers | No explicit license; published for research | Old-era comparison and the spam slice only |

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

## Pipeline

| Step | Command | Writes | Time on my laptop |
|---|---|---|---|
| Download and verify | `make data-download` | `data/raw/<source>/`, with a `MANIFEST.json` per source | about 2.5 GB, once |
| Parse into one record format | `make data-build` | `data/interim/records.jsonl.gz` | about 4 min |
| Mask fingerprints, remove duplicates | `make data-prepare` | `data/interim/masked.jsonl.gz`, `dedup.json`, `index.json` | about 2.5 min |
| Build the splits | `make data-splits` | `data/splits/splits.json` (ids) and `summary.json` (counts) | under 1 s |
| Leakage audit | `make audit` | [`reports/leakage_audit.md`](../reports/leakage_audit.md) (committed) | about 15 s |

`make data` runs the first four steps. The scripts print counts only, never email content.

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

The masked record (`mask.py`) has the same fields, with fewer headers and one extra field, `auth` (see below).

Spam is kept as its own label. It is not phishing, and I report it only as a separate "hard negative"
slice.

## Counts before cleaning

Measured on 2026-10-30 by `make data-build`, before masking and de-duplication.

| Source | Class | Messages | Dated from `Received:` | Years with most mail |
|---|---|---:|---:|---|
| Nazario | phishing | 12,010 | 99.9% | 2005–2007 (5,428); 2015–2025: 3,662 |
| phishing_pot | phishing | 12,864 | 99.9% | 2023–2026 (12,648); 2026 alone: 6,235 |
| Apache (5 lists) | legitimate | 95,990 | 100% | 2015–2018 (51,753), falling to about 3,000 a year by 2025–2026 |
| SpamAssassin | legitimate | 6,951 | 97.5% (whole corpus) | 2002 |
| SpamAssassin | spam | 3,794 | | 2001–2002 |

- Nazario's `private-phishing4.mbox` turned out to cover mid-2007 to 2015 (3,534 messages, 2,834 of
  them from 2008–2014).
- Fewer than 0.1% of messages had a parse error (malformed headers or unknown character sets); they are
  kept, and the error is recorded on the record.

## Masking source fingerprints

Each source was collected by a different inbox, and the receiving side leaves marks that have nothing to do
with phishing. I counted header presence and recipient addresses per source:

- **phishing_pot:** 27 `X-MS-*` and `X-Microsoft-*` headers (plus other Exchange headers) on at least 95% of
  messages, because the honeypot inbox is Microsoft 365; the recipient is redacted to `phishing@pot` in 94%.
- **Apache:** `Mailing-List`, `List-*` and `Precedence` on 100%; delivery to the archive's `ponee.io` address on
  79%; `X-Spam-*` on 70%; subject tags like `[users@httpd]`; an unsubscribe footer in 47% of bodies.
- **Nazario:** `Status` and `X-Keywords` from the mail client on 100%; delivered to `jose@monkey.org` addresses
  in 62% (most of the rest are already redacted to `example.com`).
- **SpamAssassin:** Mailman `List-*` headers on 55–63%, recipients redacted to `yyyy@` and `zzzz@`.

`mask.py` applies the same rules to every source:

- keep only 16 headers the sender writes (`From`, `Reply-To`, `To`, `Subject`, `Content-Type`, `X-Mailer`,
  `User-Agent`, `DKIM-Signature` signing domain, ...), in one fixed order, because Microsoft 365 reorders
  headers. `Return-Path` and `Sender` are dropped because mailing lists rewrite them; `Message-ID`,
  `In-Reply-To` and `References` because their domains name the servers involved;
- move the receiving server's `Authentication-Results` out of the headers into a separate `auth` field
  (`spf=pass dkim=fail ...`, without the server name), for the rule-based sender check;
- for list mail, remove the subject tag, a `Reply-To` that points back to the list, and the unsubscribe footer
  (also when it is quoted in a reply);
- replace recipient addresses with `user@example.com`, the collection domains (`monkey.org`, `ponee.io`,
  `taint.org`, ...) with `example.com`, the collectors' names (`jose`, `yyyy`) with `user`, and the Apache lists'
  own names (`apache`, `tomcat`, `cassandra`, `httpd`) with `project`. These names are this dataset's version of
  the `enron` that leaked the label in my course project.

The date is kept on the record, because the splits need it; month matching (below) makes it carry no label
signal.

## Duplicates removed

Duplicates are found on the masked text, so an announcement cross-posted to two Apache lists counts as one
email. Exact copies match after lowercasing and replacing numbers, links and addresses; near copies are found
with MinHash LSH (128 permutations, word 5-grams, estimated Jaccard similarity of 0.9 or more). Each group keeps
its earliest email.

| Source | Class | Before | Exact copies | Near copies | Label conflicts | Empty | Kept | Removed |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Apache | legitimate | 95,990 | 2,310 | 9,077 | 2 | 8 | 84,593 | 11.9% |
| Nazario | phishing | 12,010 | 2,191 | 2,300 | 7 | 45 | 7,467 | 37.8% |
| phishing_pot | phishing | 12,864 | 2,411 | 1,437 | 0 | 6 | 9,010 | 30.0% |
| SpamAssassin | legitimate | 6,951 | 2,814 | 65 | 0 | 0 | 4,072 | 41.4% |
| SpamAssassin | spam | 3,794 | 1,956 | 331 | 0 | 0 | 1,507 | 60.3% |
| **Total** | | **131,609** | | | **9** | **59** | **106,649** | **19.0%** |

- About a third of the phishing is copies of other phishing: campaigns resend one message with a different
  link or name. Left in, the same campaign would sit in both training and test data.
- The exact copies include 1,594 byte-identical files, almost all from SpamAssassin's 2003 releases, which
  repeat the 2002 ones.
- Apart from the label conflicts below, no duplicate group crossed sources.
- The 9 label conflicts are one template ("your password will expire soon, click here...") found in Nazario's
  phishing and in two Apache list posts: phishing that reached a public list. Every email in a group that mixes
  labels is dropped.
- The 59 empty emails have no subject, body text or attachment, so there is nothing to learn from them.

## Splits

Built by `splits.py` with seed `20261029`; re-running it gives byte-identical files.

**Main pool (month-matched):** every month from 2015-01 to 2026-09 has the same number of phishing and
legitimate emails, so the date alone says nothing about the label. That gives 9,469 phishing (2,817 Nazario,
6,652 phishing_pot) and 9,469 legitimate emails. Left out:

- 75,115 Apache emails from months with more legitimate mail than phishing;
- 2,008 phishing emails from months with less legitimate mail, mostly 2026 (1,933 from phishing_pot);
- 355 phishing_pot emails from October 2026, after the last Apache month I downloaded, and 5 undated ones.

| Split | Question it answers | Train | Val | Test |
|---|---|---:|---:|---:|
| `random` | The "normal" number | 13,258 | 2,840 | 2,840 |
| `by_source/nazario_to_phishing_pot` | Does it catch phishing from a source it never saw? | 4,788 | 846 | 13,304 |
| `by_source/phishing_pot_to_nazario` | The same, the other way round | 11,308 | 1,996 | 5,634 |
| `by_time` | Train on 2015–2022, test on 2023–2026: does it age? | 3,242 | 572 | 15,124 |
| `by_time_nazario` | Train on 2015–2020, test on 2021–2025, Nazario only | 2,464 | 434 | 2,736 |
| `old_era` | Nazario 2004–2014 vs SpamAssassin 2002, confounded on purpose | 6,096 | 1,306 | 1,307 |
| `spam` | Spam as a hard negative (test only) | | | 1,507 |

Every main-pool split is half phishing and half legitimate. In Phase 2 I compute precision at a realistic base
rate from the measured rates, instead of changing the split.

- In `by_source`, each legitimate email goes with the phishing email it was matched to, so both sides stay
  month-matched. There is only one legitimate source, so this tests new phishing only.
- In `by_time`, the training phishing is mostly Nazario (1,465 of 1,621) and the test phishing mostly
  phishing_pot (6,462 of 7,562), so time and source are mixed. `by_time_nazario` keeps one source, so the
  difference between the two is the effect of the source.
- `old_era` has 4,637 phishing and 4,072 legitimate emails from different years. It reproduces the course
  project's setup, to show how inflated such a score is.

## Leakage audit

`audit.py` trains a logistic regression on groups of features that should not predict phishing, on the
`random` split, and reports ROC AUC on its test part. 0.5 means no signal; 1.0 means the group alone
separates the classes. Full results with the strongest features: [reports/leakage_audit.md](../reports/leakage_audit.md).

| Feature group | Raw records | Masked records |
|---|---:|---:|
| Header names | 1.000 | 0.776 |
| Header order | 1.000 | 0.787 |
| Recipient domain | 1.000 | 0.571 |
| `Authentication-Results` | 0.996 | 0.500 (moved to `auth`) |
| Message-ID domain | 0.922 | 0.500 (dropped) |
| Date (year, month) | 0.470 | 0.470 |
| Text (subject and body, TF-IDF) | 1.000 | 0.999 |

What this shows:

- **On raw records, the headers alone identify the dataset perfectly.** A model trained on them would learn
  which inbox collected the email.
- **After masking, recipients, server names and dates carry no label signal.** The remaining header signal
  (about 0.78) is which mail program wrote the email: `User-Agent` and `Content-Language` from people's mail
  clients on the lists, `X-Priority` and `Importance` from bulk-mail tools in phishing. That is partly a real
  signal and partly this dataset, so I won't use header names as model features directly.
- **The `auth` field on its own scores 0.993.** Which results exist at all depends on the collecting server,
  so it stays out of the learned features, and the sender check uses it as rules instead.
- **The text still separates the classes almost perfectly (0.999).** After masking, the strongest legitimate
  words are `project`, `wrote`, `hi`, `thanks`, `re` and `java`: mailing-list conversation. The strongest
  phishing words are `your`, `account`, `click` and `wallet`. With one legitimate source, a random split on
  this data will score near 100%, so the by-source and by-time splits and the private test inbox matter more
  than the random number.
- **The two phishing sources differ (text AUC 0.982):** crypto-wallet scams in phishing_pot, bank and mailbox
  phishing in Nazario. That makes `by_source` a real test of new phishing.
- **On the confounded `old_era` split, the date alone scores 1.000:** the trap my course project fell into.

## Known limits

- **Legitimate mail is mailing-list mail.** It is technical discussion and announcements, not the bank,
  shop and job notifications that phishing imitates. The text audit (0.999 after masking) measures how easy
  that makes the task; the private test inbox exists to measure the gap.
- **List mail is not always legitimate.** Two Apache list posts turned out to be phishing (found as label
  conflicts), so a few spam or phishing posts that got past the lists' filters may still be labelled
  legitimate.
- **Each phishing source comes from a few collection inboxes,** so it is not representative of any one
  person's or company's mail.
- **The `Authentication-Results` header looks different in every source.** Measured share of messages with
  SPF/DKIM/DMARC results:

  | Source | Has results | Who wrote them |
  |---|---:|---|
  | phishing_pot | 99.7% | Microsoft 365 format (no server name) |
  | Apache | 55.0% | Apache's own mail and spam-filter servers |
  | Nazario | 19.6% | hostedemail.com (mostly recent years) |
  | SpamAssassin | 0% | (mail from before SPF/DKIM existed) |

  So `auth` is kept out of the learned features. The private test inbox, where every message carries Gmail's
  real results, is the fair test for the sender check.
- **Some header signals can't be learned from this data.** The masked record has no `Received:`,
  `Return-Path` or `Sender` headers, because the collecting side or the list software wrote them. A hop count
  or a From vs Return-Path mismatch would mostly measure the source here.
- **Apache ids can change.** The Apache archive generates its mbox files on request, so the bytes, and
  therefore the ids and splits, can differ if the archive changes. The other sources are pinned by checksum.
- **Mostly English.**
