# phish-triage for Gmail

A Gmail sidebar for my phish-triage API, written in Google Apps Script ([Code.js](Code.js)). I open an email and
nothing happens until I click a button:

- **Scan** sends the open email to `POST /v1/scan` and shows the verdict, the score next to the threshold it is
  compared with, the sender check and its warnings, and the signals.
- **Explain** sends it to `POST /v1/explain`, which runs the analyst step with Claude and shows the summary, what to
  do, and each sign with its evidence. Only this button sends an email to Anthropic.
- **Correct / False alarm / Missed phishing** send the scan id and the label, nothing else.
- **Send as phishing / Send as legitimate** is the one button that asks the API to keep the email: it goes to my
  private retraining bucket with that label, for at most 90 days (`make retrain` uses it and deletes it).

## What it can reach

- **Mail:** only the open message (`gmail.addons.current.message.readonly`), not the rest of my mailbox. It reads the
  message's original source (`getRawContent`). Google's reference lists only the full-mail scope for that, but on
  my first install it worked with this one; if it ever doesn't, the add-on rebuilds the email from its headers and
  body and says so on the result.
- **Network:** only the API address in the manifest's `urlFetchWhitelist`.
- **Storage:** the API address and my API key, in my own user properties. It logs nothing.

The API stores the verdict, the score and the email's SHA-256, never the email (docs/THREAT_MODEL.md, rule 8).

**Not in Spam.** Gmail doesn't run add-ons on messages in Spam or marked suspicious ("Spam and suspicious messages
can't be used for recommended content or actions"), so the add-on can't scan, explain or send for retraining the
phishing Gmail has already caught. The brand-lookalike signal also fires on mailing services' tracking domains that
carry a brand in their name (a `comcastdotcom-...` subdomain of an email-marketing service, say): that is the
pattern phishers use, so the signal shows, though the verdict on those emails was safe.

## How I install it

The API address isn't committed, so the manifest is a template. `make addon` fills it in from
`~/.config/phish-triage/api-url` (or `ADDON_API_URL=...`) and writes `build/addon/Code.js` and
`build/addon/appsscript.json`. Then, in my own Google account:

1. At [script.google.com](https://script.google.com) I create a new project named phish-triage, in the same Google
   account whose Gmail I use it in (a test install only runs for the script owner's domain).
2. In Project Settings I tick "Show appsscript.json manifest file in editor".
3. I paste `build/addon/Code.js` over `Code.gs`, and `build/addon/appsscript.json` over `appsscript.json`, and save.
4. Deploy → Test deployments (not New deployment) → Google Workspace Add-on → Install → Done. Then I reload Gmail.
5. In an email I open the phish-triage icon on the right and grant the permissions. Google first warns "Google
   hasn't verified this app": that is my own unpublished project, and verification is only for publishing to other
   people. The permissions asked for are the three in the manifest (view the open message while the add-on runs,
   run as a Gmail add-on, connect to an external service); anything more would mean the wrong manifest.
6. In Settings I enter the API address and my key.

A test deployment runs the code as it is in the editor, for my account only; nothing is published.

**Not on my test-inbox account.** That inbox is a test set and never goes to an LLM, and Explain would send its
emails to Claude; the service's private-data guard knows the inbox's ids only on my laptop, not in AWS. So the
add-on lives in my personal account.
