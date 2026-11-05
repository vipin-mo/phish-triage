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
| [Naser Alam's Kaggle phishing email dataset](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset) (version 1), built from [Champa et al., Zenodo 8339691](https://zenodo.org/records/8339691) | "phishing" (mostly spam) + legitimate | mostly 2000–2008; its Nazario part is 2015–2019 | CSV, cleaned text, no headers | CC BY-SA 4.0 / CC-BY-4.0 | My course project's data: reproducing its score only ([reports/course_reproduction.md](../reports/course_reproduction.md)). Downloading it needs a Kaggle API token; without one `make data-download` skips it |
| [Greco et al.'s human- and LLM-written emails](https://www.kaggle.com/datasets/francescogreco97/human-llm-generated-phishing-legitimate-emails) (version 1) | LLM-written phishing | — | CSV, body text only | CC BY-NC-SA 4.0 (non-commercial) | A robustness test only, never trained on ([reports/robustness.md](../reports/robustness.md), `data/greco.py`): its 1,000 LLM-written phishing emails. Its human-written half overlaps my sources (Nazario's phishing; CEAS, SpamAssassin and openSUSE mail), and its LLM-written "legitimate" file is labelled phishing on every row and partly reads as phishing, so neither is used as a test. Same Kaggle token as above |

The Apache lists are `announce@apache.org`, `users@httpd`, `users@tomcat`, `user@cassandra` and
`dev@community`: announcements, user support and project discussion from different communities.

**Private data (never committed, never sent to an LLM):**

| Source | Why | License |
|---|---|---|
| A private test inbox (a new Gmail account subscribed to newsletters, shops and job sites) | Realistic notification-style legitimate mail. Never committed or sent to an LLM; only counts and metrics are published. Part of it, split by sender, is in the `with_inbox` training split (`data/inbox.py`) | private |
| [PrivacyMail](https://zenodo.org/records/6509751) (Maass, Schwär and Hollick, 2019), about 500,000 newsletters from 1,423 websites, 2019–2022 | Commercial newsletters from many senders: a false-alarm test, then part of the `with_newsletters` training split, split by website (`data/privacymail.py`). Read from the zip without unpacking; never committed or sent to an LLM; only counts and metrics are published, website names hashed | on request; the owner allows models trained on it to be used and published, not the newsletters themselves |

**Planned, not yet added:**

| Source | Why | License |
|---|---|---|
| A second legitimate source (e.g. another public mailing-list archive) | Cross-source test for the legitimate class | to be checked |

**Reference data (not emails):**

| Data | Used for | License |
|---|---|---|
| [Tranco top-1M list](https://tranco-list.eu/list/746VX), list `746VX` (generated 2026-10-30), pinned by checksum | Domain popularity features and the sender check | Research use; combines ranking lists that have their own licenses (some CC BY-NC 4.0) |

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
- Maass, Schwär and Hollick, PrivacyMail newsletter dataset (APF 2019), <https://zenodo.org/records/6509751>
  (access on request; not redistributed).
- The Apache SpamAssassin project, public corpus, <https://spamassassin.apache.org/old/publiccorpus/>.
- Naser Abdullah Alam, Phishing Email Dataset, Kaggle, built from Champa et al., "Phishing Email Curated
  Datasets", Zenodo 8339691 (CC-BY-4.0).
- Le Pochat et al., "Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation", NDSS 2019;
  list `746VX`, <https://tranco-list.eu/list/746VX>.

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
  `taint.org`, ...) with `example.com`, and the collectors' names (`jose`, `yyyy`) with `user`. In `Reply-To` only
  the collectors' own are replaced: a recipient named there is where replies really go, and until November 2026
  masking it created a false "replies go to a different domain" in 319 of the 9,338 Apache emails (now 0);
- replace the Apache lists' own names (`apache`, `tomcat`, `cassandra`, `httpd`) with `project`. These names are
  this dataset's version of the `enron` that leaked the label in my course project. In the subject and the plain
  text they are replaced everywhere, URLs and addresses included (`tomcat.apache.org` becomes
  `project.project.org`), so no text model can read the source from a link. In the HTML, URLs, addresses and
  domain names keep the real name, and so does the separate URL list, because the link features (where a link
  goes, what its text shows) need the real domain. The text models read the visible HTML text, so the names are
  replaced there again, URLs included, before a model sees it. The leakage audit checks that the real domains
  don't become a shortcut (below). The analyst step sees the names, as a subscriber would: it isn't trained on
  this data, so they can't become a learned shortcut.

  Until November 2026 the replacement also ran over the HTML, so 807 legitimate HTML emails had link targets like
  `project.project.org`, and the link list shown to Claude (real domains from the URL list) didn't match the body
  (`project.org`). I found it while rating the analyst's answers by hand; every number on this page and in the
  reports was re-measured after the fix. When the text models moved to the visible HTML text, also in November
  2026, the names in its links and addresses reached them in 753 legitimate emails (5.6%) and no phishing, until
  that text was masked too. The leakage audit's text test now reads exactly what the models read, so it would show
  such a leak.

The date is kept on the record, because the splits need it; month matching (below) makes it carry no label
signal.

## Duplicates removed

Duplicates are found on the masked text, so an announcement cross-posted to two Apache lists counts as one
email. For HTML mail the compared text is what a reader sees (the visible text of the HTML part), because some
phishing pads every copy with about 30,000 characters of different hidden filler so the full texts look
unrelated. Exact copies match after lowercasing and replacing numbers, links and addresses; near copies are found
with MinHash LSH (128 permutations, word 5-grams, estimated Jaccard similarity of 0.9 or more). Each group keeps
its earliest email.

Until November 2026 the full text was compared. Comparing the visible text removed 395 more phishing emails (233
Nazario, 162 phishing_pot) and 751 more Apache emails, mostly HTML notifications from one template.

| Source | Class | Before | Exact copies | Near copies | Label conflicts | Empty | Kept | Removed |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Apache | legitimate | 95,990 | 2,306 | 9,832 | 2 | 8 | 83,842 | 12.7% |
| Nazario | phishing | 12,010 | 2,240 | 2,484 | 7 | 45 | 7,234 | 39.8% |
| phishing_pot | phishing | 12,864 | 2,591 | 1,419 | 0 | 6 | 8,848 | 31.2% |
| SpamAssassin | legitimate | 6,951 | 2,801 | 75 | 0 | 0 | 4,075 | 41.4% |
| SpamAssassin | spam | 3,794 | 1,958 | 327 | 0 | 0 | 1,509 | 60.2% |
| **Total** | | **131,609** | | | **9** | **59** | **105,508** | **19.8%** |

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
legitimate emails, so the date alone says nothing about the label. That gives 9,338 phishing (2,786 Nazario,
6,552 phishing_pot) and 9,338 legitimate emails. Left out:

- 74,495 Apache emails from months with more legitimate mail than phishing;
- 1,942 phishing emails from months with less legitimate mail, mostly 2026 (1,878 from phishing_pot);
- 354 phishing_pot emails from October 2026, after the last Apache month I downloaded, and 5 undated ones.

| Split | Question it answers | Train | Val | Test |
|---|---|---:|---:|---:|
| `random` | The "normal" number | 13,072 | 2,802 | 2,802 |
| `by_source/nazario_to_phishing_pot` | Does it catch phishing from a source it never saw? | 4,736 | 836 | 13,104 |
| `by_source/phishing_pot_to_nazario` | The same, the other way round | 11,138 | 1,966 | 5,572 |
| `by_time` | Train on 2015–2022, test on 2023–2026: does it age? | 3,218 | 568 | 14,890 |
| `by_time_nazario` | Train on 2015–2020, test on 2021–2025, Nazario only | 2,454 | 434 | 2,684 |
| `old_era` | Nazario 2004–2014 vs SpamAssassin 2002, confounded on purpose | 5,961 | 1,277 | 1,277 |
| `spam` | Spam as a hard negative (test only) | | | 1,509 |
| `with_inbox` (private) | `random` plus part of my test inbox, split by sender, and as many 2026 phishing emails | 13,946 | 3,104 | 4,695 |
| `with_newsletters` (private, deployed) | `with_inbox` plus PrivacyMail newsletters, split by website (at most 10 per website in train and val, at most 25 in test) | 18,724 | 4,699 | 8,433 |

Every main-pool split is half phishing and half legitimate. In Phase 2 I compute precision at a realistic base
rate from the measured rates, instead of changing the split.

- In `by_source`, each legitimate email goes with the phishing email it was matched to, so both sides stay
  month-matched. There is only one legitimate source, so this tests new phishing only.
- In `by_time`, the training phishing is mostly Nazario (1,446 of 1,609) and the test phishing mostly
  phishing_pot (6,362 of 7,445), so time and source are mixed. `by_time_nazario` keeps one source, so the
  difference between the two is the effect of the source.
- `old_era` has 4,440 phishing and 4,075 legitimate emails from different years. It reproduces the course
  project's setup, to show how inflated such a score is.

## Leakage audit

`audit.py` trains a logistic regression on groups of features that should not predict phishing, on the
`random` split, and reports ROC AUC on its test part. 0.5 means no signal; 1.0 means the group alone
separates the classes. Full results with the strongest features: [reports/leakage_audit.md](../reports/leakage_audit.md).

| Feature group | Raw records | Masked records |
|---|---:|---:|
| Header names | 1.000 | 0.782 |
| Header order | 1.000 | 0.799 |
| Recipient domain | 1.000 | 0.573 |
| `Authentication-Results` | 0.996 | 0.500 (moved to `auth`) |
| Message-ID domain | 0.919 | 0.500 (dropped) |
| Date (year, month) | 0.467 | 0.467 |
| Text the models read (TF-IDF) | 1.000 | 1.000 |

What this shows:

- **On raw records, the headers alone identify the dataset perfectly.** A model trained on them would learn
  which inbox collected the email.
- **After masking, recipients, server names and dates carry no label signal.** The remaining header signal
  (about 0.78–0.80) is which mail program wrote the email: `User-Agent` and `Content-Language` from people's mail
  clients on the lists, `X-Priority` and `Importance` from bulk-mail tools in phishing. That is partly a real
  signal and partly this dataset, so I won't use header names as model features directly.
- **The `auth` field on its own scores 0.994.** Which results exist at all depends on the collecting server,
  so it stays out of the learned features, and the sender check uses it as rules instead.
- **The text still separates the classes almost perfectly (1.000).** This test reads what the text models read:
  the subject and the visible text, without dates. After masking, the strongest legitimate words are `project`,
  `org`, `wrote`, `https`, `re`, `hi` and `thanks`: mailing-list conversation, links written out in full, and the
  placeholder itself (`project`, `org` from `project.org` links), which is the price of masking the names. The
  strongest phishing words are `your`, `account`, `click` and `wallet`. With one legitimate source, a random split
  on this data will score near 100%, so the by-source and by-time splits and the private test inbox matter more
  than the random number.
- **The two phishing sources differ (text AUC 0.979):** crypto-wallet scams in phishing_pot, bank and mailbox
  phishing in Nazario. That makes `by_source` a real test of new phishing.
- **On the confounded `old_era` split, the date alone scores 1.000:** the trap my course project fell into.
- **The source's own domain is not a shortcut.** Links keep their real domains, and `apache.org` is in 46.2% of
  the legitimate emails and none of the phishing. Link domains as tokens would separate the classes well (0.942,
  `apache.org` and `github.com` on the legitimate side), but no model uses them that way. The link features the
  models do use score 0.9732 on their own and 0.9673 with every link to `apache.org` removed. The rule, set before
  the first run, was that losing more than 0.01 makes it a shortcut; it loses 0.006.

## Known limits

- **Legitimate mail is mailing-list mail.** It is technical discussion and announcements, not the bank,
  shop and job notifications that phishing imitates. The text audit (1.000 after masking) measures how easy
  that makes the task; the private test inbox measures the gap: the models flag 96.8–99.9% of its 1,677
  legitimate emails ([reports/test_inbox.md](../reports/test_inbox.md)). With part of the inbox in training,
  split by sender, the cascade flags 4.0% of the emails from 26 unseen senders
  ([reports/with_inbox.md](../reports/with_inbox.md)), but 76.5% of 18,682 PrivacyMail newsletters from 944
  websites ([reports/privacymail.md](../reports/privacymail.md)): 26 senders were too few. With part of PrivacyMail
  in training too, split by website, it flags 0.9% of newsletters from 189 held-out websites and 2.0% of the
  inbox's unseen senders.
- **My inbox's legitimate mail is all bulk mail from large senders,** so on it the number of links and an
  own-domain DKIM signature mark legitimate mail (ROC AUC 0.92–0.96 on their own, against 0.51–0.58 on the public
  test). The cascade decides the same without them; what it misses more is phishing that reads like a
  newsletter: 25 of 31 caught, and 23 of 31 with the PrivacyMail newsletters in training. The newsletters fill
  the legitimate side; I found no public source of newsletter-like phishing for the other side.
- **PrivacyMail is not a random sample of anyone's inbox.** Its users chose which websites to sign up to, only 944
  of its 1,423 websites sent English mail I could use (I keep only English), and it ends in 2022, so the
  held-out-websites test is the easier one and my inbox the harder one.
- **A few test senders were also in training, across the two private sources.** The inbox was split by sender
  and PrivacyMail by website, separately, so 5 of the 249 inbox test emails (2 of 26 senders) and 43 of the 3,738
  held-out newsletters (5 sender domains) share a registered sender domain with training. Without them the
  deployed cascade flags 2.05% (5 of 244) and 0.84% (31 of 3,695), against 2.01% and 0.86%, so the reported numbers
  hold. No test email is an exact text copy of a training one. The next build of the split groups websites by
  sender domain and puts a website that shares a sender with the inbox where that sender is.
- **The private sources' own collection names reached the model input a little.** PrivacyMail's collection
  domains appear in 0.2% of its emails as the models read them (17 of 10,111), my inbox's address in 0.4% (3 of
  837), and neither in any public email: too rare to be the shortcut the public collectors were, but masked from
  the next build (`make private-collectors`, kept in data/private).
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
