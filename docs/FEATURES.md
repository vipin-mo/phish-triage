# Features and the sender check

Two kinds of signal come out of every email, both computed from the masked record (`src/phish_triage/data/mask.py`),
which is the same view the service will build from a live email:

- **Structured features** (`src/phish_triage/features/extract.py`): 42 numbers the gradient-boosted trees learn
  from. Each one is a standard phishing signal I can explain.
- **The sender check** (`src/phish_triage/features/sender.py`): a rule-based answer to "is the sender who they
  claim to be?", meant to be shown to the user. It is not a learned feature (see below).

Nothing is fetched while computing either: URLs are parsed as strings, and domain facts come from offline lists
(tldextract's bundled public-suffix list and a pinned Tranco top-1M snapshot).

## Structured features

| Group | Features | What they catch |
|---|---|---|
| Sender | `from_missing`, `from_free_mail`, `from_log_rank`, `from_lookalike`, `display_name_brand_mismatch`, `display_name_has_other_address`, `reply_to_differs`, `reply_to_free_mail_differs`, `to_missing`, `dkim_signed`, `dkim_aligned` | A display name that says "PayPal" on someone else's domain, replies routed to a free-mail inbox, unknown or look-alike sender domains, mail sent to undisclosed recipients |
| Links | `n_urls`, `n_link_domains`, `ip_url`, `punycode_url`, `confusable_url`, `lookalike_url`, `shortener_url`, `url_with_credentials`, `http_share`, `max_url_length`, `max_subdomain_depth`, `link_text_mismatch`, `brand_mentioned_not_linked`, `max_link_log_rank`, `unranked_link_share` | A link that shows one domain and goes to another, links to IP addresses, `xn--` or look-alike letters, shorteners, a brand named in the text that none of the links belong to, links to domains outside the top 1M |
| HTML | `has_html`, `html_form`, `password_input`, `html_script`, `n_images` | Forms and password fields inside the email, scripts, image-heavy mail |
| Attachments | `n_attachments`, `risky_attachment`, `html_attachment`, `archive_attachment`, `macro_attachment` | `.html`, `.iso`, `.zip`, `.js`, macro-enabled Office files |
| Wording | `log_words`, `urgency_terms`, `credential_terms`, `payment_terms`, `exclamations`, `recipient_address_in_body` | "Suspended within 24 hours", "verify your password", invoices and gift cards, the recipient's own address pasted into the text |

**Look-alike domains** (`domains.lookalike_brand`): a brand name as a word of someone else's domain
(`paypal-secure.com`, `paypal.com.evil.test`), or a word of the domain one or two letters away from a brand name of
six or more letters (`paypa1.com`, `micros0ft-support.net`). Only substitutions and insertions count, because
deleting a letter often gives a real word (`icloud` -> `cloud`), and short brand names are common words (`chase`,
`apple`), so they are matched only as whole words.

**Missing is not zero.** When an email has no headers at all, as in text-only datasets, every sender feature is
missing (NaN), never 0. The trees handle missing values natively.

### Left out on purpose

| Signal | Why it is not a feature |
|---|---|
| SPF / DKIM / DMARC results | The leakage audit showed they identify the collecting server (AUC 0.993 on their own). They drive the sender check instead. |
| Number of `Received` hops | Set mostly by the collecting side, so here it would measure the dataset |
| From vs `Return-Path` mismatch | Mailing lists rewrite `Return-Path`, so every list email would "mismatch" |
| Header names and order | Identify the mail program and the collector (AUC 0.78 after masking) |

## The sender check

It reads SPF, DKIM and DMARC only from the receiving provider's own `Authentication-Results` header: the topmost
one (threat model, rule 14). Lower copies may have been written by the sender, so they are ignored, and a lower copy
claiming a pass that the provider's header did not give is reported as a warning. Nothing is re-verified with DNS.

| Verdict | When |
|---|---|
| `fail` | DMARC fails, or SPF fails while DKIM doesn't pass, or DKIM fails while SPF doesn't pass |
| `pass` | DMARC passes, or DKIM passes with a signature from the `From` domain itself |
| `partial` | Results exist but aren't conclusive |
| `none` | No results (old mail, or a provider that adds none) |

Warnings are reported next to the verdict: a look-alike sender domain, a brand in the display name that the address
doesn't belong to, replies going to a different domain, a sender domain outside the top 1M, and the forged lower
copy above.

**"Pass" does not mean safe.** It means the `From` domain really sent the email. Phishers' own look-alike domains
pass SPF and DKIM too, which is why the warnings sit next to the verdict.

The sender check is tested on hand-made emails (`tests/fixtures/spoofed_brand.eml`, `clean_newsletter.eml`). Its
fair evaluation is the private test inbox, where every email carries Gmail's real results; the public datasets
can't show it, because their results depend on who collected them.
