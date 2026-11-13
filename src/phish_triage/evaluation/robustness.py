"""How much do simple evasion tricks cost the deployed cascade, and does LLM-written phishing get through?

    python -m phish_triage.evaluation.robustness cascade            # the attacks on the deployed cascade ($0)
    python -m phish_triage.evaluation.robustness plan               # the analyst sample's cost (no API)
    python -m phish_triage.evaluation.robustness run --confirm      # the analyst sample, Claude Haiku (costs money)
    python -m phish_triage.evaluation.robustness rescore            # re-check the saved answers (no API)

The attacks were set before the first run, and none was tuned on its results:

- **look-alike letters:** 30% of the letters that have a Cyrillic twin (a c e o p x y i s j, and A B C E H K M O P T X)
  swapped for it, in the subject and the text; links, addresses and HTML markup untouched.
- **hidden characters:** a zero-width space in the middle of every word of four letters or more.
- **hidden HTML:** a harmless paragraph, three times (about 360 words), hidden at the top of the body, by four tricks:
  inline `display:none` (which the visible-text reader drops: a control), a class hidden by a `<style>` block, a
  block moved off-screen, and 2 px text. A plain-text email gets an HTML part with its own text.
- **shortened links:** every link replaced by a bit.ly link.
- **all four:** shortened links, then look-alike letters, hidden characters and the `<style>` class trick.

One row was added after the first run, to explain it: the `<style>` class trick with the paragraph at the end of
the body instead of the top.

They run on the public `random` test's phishing (none of it in the deployed bundle's training data) and on Greco et
al.'s LLM-written phishing (`data/greco.py`), with the deployed bundle one email at a time, as the service runs it.
For each: the cascade's verdict, the stage that decided, and DistilBERT's verdict on every email, so a stage-1
decision doesn't hide what DistilBERT would have said.

The analyst sample: 20 phishing emails from the fixed Claude sample (`reports/analyst.md`), each clean and under each
attack but the hiding controls (the `<style>` class stands for hidden HTML), through the defended analyst behind the
deployed cascade, as `analyst_eval` runs it. Public emails only; `analyst.render` refuses private ones.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import html as html_lib
import json
import random
import re
import sys
from collections import Counter
from pathlib import Path

from phish_triage.data.parse import TRAILING_PUNCT, URL_RE, extract_urls, html_to_text

REPORTS_DIR = Path("reports")
SEED = 20261105
LOOKALIKE_SHARE = 0.3
LATIN = "aceopxyisjABCEHKMOPTX"
CYRILLIC = "асеорхуіѕјАВСЕНКМОРТХ"
TWINS = dict(zip(LATIN, CYRILLIC, strict=True))
ZERO_WIDTH = "​"
HIDDEN_COPIES = 3
HARMLESS = (
    "Thank you for being part of our reading group this season. The library has extended its weekend hours, and the "
    "reading room on the second floor is open again after the repairs. Our next meeting is on Thursday evening, when "
    "we will talk about the first half of the book and share notes from last month. Tea and biscuits will be served "
    "as usual. If you would like to suggest a title for the winter list, please bring it along or mention it to one of "
    "the volunteers at the front desk. We are also collecting used books for the spring sale, so feel free to drop "
    "off any you no longer need. See you soon."
)
HIDING = {  # (what goes before the body, the hidden block)
    "display_none": ("", '<div style="display:none">{}</div>'),
    "style_class": ("<style>.note{display:none}</style>", '<div class="note">{}</div>'),
    "off_screen": ("", '<div style="position:absolute;left:-9999px;top:-9999px">{}</div>'),
    "tiny_text": ("", '<div style="font-size:2px">{}</div>'),
}
# Held out (Phase 7.2, part 2): set before the defence was written. Reader 2 has no rule for text-indent, clip or
# transform, which test whether it generalizes. Its <style> rule covers the id and tag tricks by design, and removing
# every format character covers the other invisible characters, so those test that design, not generalization.
GREEK_LATIN = "aoipvxkABEHIKMNOPTXYZ"
GREEK = (
    "\u03b1\u03bf\u03b9\u03c1\u03bd\u03c7\u03ba"  # a o i p v x k
    "\u0391\u0392\u0395\u0397\u0399\u039a\u039c\u039d\u039f\u03a1\u03a4\u03a7\u03a5\u0396"  # capitals
)
GREEK_TWINS = dict(zip(GREEK_LATIN, GREEK, strict=True))
OTHER_INVISIBLE = ("\u200c", "\u200d", "\u2060", "\u00ad", "\ufeff")  # joiners, word joiner, soft hyphen, BOM
HELD_OUT_HIDING = {
    "id_in_style": ("<style>#pre{display:none}</style>", '<div id="pre">{}</div>'),
    "tag_in_style": ("<style>aside{visibility:hidden}</style>", "<aside>{}</aside>"),
    "text_indent": ("", '<div style="text-indent:-9999px;overflow:hidden;white-space:nowrap">{}</div>'),
    "clip": ("", '<div style="position:absolute;clip:rect(0 0 0 0);width:1px;height:1px;overflow:hidden">{}</div>'),
    "scale_zero": ("", '<div style="transform:scale(0)">{}</div>'),
}
# Held out again (2026-11-13), set before any run: reader 3 has rules for text-indent, clip and transform, so those
# are no longer held out. These six hide text from a person and reader 3 has no rule for any of them (checked on the
# reader alone, before measuring recall); none is in any training copy.
HELD_OUT_2_HIDING = {
    "media_query": ("<style>@media screen{.pre{display:none}}</style>", '<div class="pre">{}</div>'),
    "off_right": ("", '<div style="position:absolute;left:9999px">{}</div>'),
    "one_px_box": ("", '<div style="height:1px;width:1px;overflow:hidden">{}</div>'),
    "transparent": ("", '<div style="color:transparent">{}</div>'),
    "filter_opacity": ("", '<div style="filter:opacity(0)">{}</div>'),
    "polygon_clip": ("", '<div style="clip-path:polygon(0 0,0 0,0 0)">{}</div>'),
}
# Text that stays as it is: links, addresses, HTML entities; and in HTML, the markup, styles, scripts and comments.
_PROTECTED = re.compile(rf"{URL_RE.pattern}|[\w.+-]+@[\w-]+(?:\.[\w-]+)+|&#?\w+;", re.IGNORECASE)
_MARKUP = re.compile(r"<(style|script)\b.*?</\1\s*>|<!--.*?-->|<[^>]*>", re.IGNORECASE | re.DOTALL)
_LONG_WORD = re.compile(r"[^\W\d_]{4,}")


def _gaps(text: str, pattern: re.Pattern, change) -> str:
    """`text` with `change` applied to the parts `pattern` doesn't match."""
    out, at = [], 0
    for m in pattern.finditer(text):
        out += [change(text[at : m.start()]), m.group()]
        at = m.end()
    return "".join([*out, change(text[at:])])


def _words(change):
    """`change` for plain text: skips the protected parts."""
    return lambda text: _gaps(text, _PROTECTED, change)


def _text_attack(record: dict, change) -> dict:
    """`change` applied to the subject, the text and the HTML's text (not its markup)."""
    r = copy.deepcopy(record)
    html = r.get("html") or ""
    derived = bool(html) and (r.get("text") or "") == html_to_text(html)
    plain = _words(change)
    r["subject"] = plain(r.get("subject") or "")
    r["headers"] = [[k, r["subject"]] if k.lower() == "subject" else [k, v] for k, v in r["headers"]]
    if html:
        r["html"] = _gaps(html, _MARKUP, plain)
    r["text"] = html_to_text(r["html"]) if derived else plain(r.get("text") or "")
    return r


def lookalike_letters(record: dict, twins: dict[str, str] = TWINS, seed: str = "lookalike") -> dict:
    rng = random.Random(f"{SEED}:{record['id']}:{seed}")
    swap = lambda text: "".join(  # noqa: E731
        twins[ch] if ch in twins and rng.random() < LOOKALIKE_SHARE else ch for ch in text
    )
    return _text_attack(record, swap)


def hidden_characters(record: dict, marks: tuple[str, ...] = (ZERO_WIDTH,)) -> dict:
    count = iter(range(10**9))

    def split(m: re.Match) -> str:
        word, mark = m.group(), marks[next(count) % len(marks)]
        return word[: len(word) // 2] + mark + word[len(word) // 2 :]

    return _text_attack(record, lambda text: _LONG_WORD.sub(split, text))


def as_html(text: str) -> str:
    paragraphs = [p for p in re.split(r"\n\s*\n", text) if p.strip()]
    return (
        "<html><body>"
        + "".join(f"<p>{html_lib.escape(p).replace(chr(10), '<br>')}</p>" for p in paragraphs)
        + ("</body></html>")
    )


def hidden_html(record: dict, trick: str, at_end: bool = False, filler: str | None = None) -> dict:
    """`filler` is the hidden text (the test's harmless paragraph by default; training copies use other text)."""
    r = copy.deepcopy(record)
    html = r.get("html") or ""
    derived = bool(html) and (r.get("text") or "") == html_to_text(html)
    if not html:
        html = as_html(r.get("text") or "")
    before, block = (HIDING | HELD_OUT_HIDING | HELD_OUT_2_HIDING)[trick]
    hidden = block.format(html_lib.escape(filler or " ".join([HARMLESS] * HIDDEN_COPIES)))
    lower = html.lower()
    at = lower.find(">", lower.find("<body")) + 1 if "<body" in lower else 0
    if at_end:
        end = lower.rfind("</body")
        end = len(html) if end < at else end
        r["html"] = html[:at] + before + html[at:end] + hidden + html[end:]
    else:
        r["html"] = html[:at] + before + hidden + html[at:]
    if derived:  # the parser derived the text from the HTML, so it would include the hidden part
        r["text"] = html_to_text(r["html"])
    r["urls"] = extract_urls(r.get("text") or "", r["html"])
    return r


def _short(url: str, host: str = "bit.ly") -> str:
    core = url.rstrip(TRAILING_PUNCT)
    return f"https://{host}/{hashlib.sha256(core.encode()).hexdigest()[:7]}{url[len(core) :]}"


def shortened_links(record: dict, host: str = "bit.ly") -> dict:
    r = copy.deepcopy(record)
    swap = lambda text: URL_RE.sub(lambda m: _short(m.group(), host), text)  # noqa: E731
    r["text"] = swap(r.get("text") or "")
    if r.get("html"):
        r["html"] = swap(r["html"])
    r["urls"] = extract_urls(r["text"], r.get("html") or "")
    return r


def all_four(record: dict, filler: str | None = None) -> dict:
    return hidden_html(hidden_characters(lookalike_letters(shortened_links(record))), "style_class", filler=filler)


ATTACKS = {
    "clean": lambda r: r,
    "lookalike_letters": lookalike_letters,
    "hidden_characters": hidden_characters,
    **{f"hidden_html_{trick}": (lambda r, t=trick: hidden_html(r, t)) for trick in HIDING},
    "shortened_links": shortened_links,
    "all_four": all_four,
    # Added after the first run, to explain it: the same trick with the paragraph at the end of the body.
    "hidden_html_style_class_at_end": lambda r: hidden_html(r, "style_class", at_end=True),
}
HELD_OUT = {
    "greek_letters": lambda r: lookalike_letters(r, GREEK_TWINS, "greek"),
    "other_invisible": lambda r: hidden_characters(r, OTHER_INVISIBLE),
    **{f"hidden_html_{trick}": (lambda r, t=trick: hidden_html(r, t)) for trick in HELD_OUT_HIDING},
    "tinyurl_links": lambda r: shortened_links(r, "tinyurl.com"),
}
HELD_OUT_2 = {f"hidden_html_{trick}": (lambda r, t=trick: hidden_html(r, t)) for trick in HELD_OUT_2_HIDING}
ANALYST_ATTACKS = (
    "clean",
    "lookalike_letters",
    "hidden_characters",
    "hidden_html_style_class",
    "shortened_links",
    "all_four",
)
ANALYST_EMAILS = 20
NAMES = {
    "clean": "Clean",
    "lookalike_letters": "Look-alike letters (30%)",
    "hidden_characters": "Hidden characters (zero-width space in every word of 4+ letters)",
    "hidden_html_display_none": "Hidden HTML: inline `display:none` (control)",
    "hidden_html_style_class": "Hidden HTML: class hidden by a `<style>` block",
    "hidden_html_off_screen": "Hidden HTML: moved off-screen",
    "hidden_html_tiny_text": "Hidden HTML: 2 px text",
    "shortened_links": "Shortened links (bit.ly)",
    "all_four": "All four",
    "hidden_html_style_class_at_end": "Check added after the first run: the `<style>` class, paragraph at the end",
    "greek_letters": "Held out: Greek look-alike letters (30%)",
    "other_invisible": "Held out: other invisible characters (joiners, word joiner, soft hyphen, BOM)",
    "hidden_html_id_in_style": "Held out: hidden by an id in a `<style>` block",
    "hidden_html_tag_in_style": "Held out: hidden by a tag rule in a `<style>` block",
    "hidden_html_text_indent": "Held out: `text-indent:-9999px`",
    "hidden_html_clip": "Held out: `clip:rect(0 0 0 0)` on a 1 px box",
    "hidden_html_scale_zero": "Held out: `transform:scale(0)`",
    "tinyurl_links": "Held out: tinyurl links",
    "hidden_html_media_query": "Held out since 2026-11-13: hidden by a `<style>` rule inside `@media screen`",
    "hidden_html_off_right": "Held out since 2026-11-13: moved off-screen to the right (`left:9999px`)",
    "hidden_html_one_px_box": "Held out since 2026-11-13: a 1 px box with `overflow:hidden`",
    "hidden_html_transparent": "Held out since 2026-11-13: `color:transparent`",
    "hidden_html_filter_opacity": "Held out since 2026-11-13: `filter:opacity(0)`",
    "hidden_html_polygon_clip": "Held out since 2026-11-13: `clip-path` with an empty polygon",
}


# --- The cascade ---


def deployed_scanner():
    from phish_triage.service.bundle import DEPLOYED_SPLIT, latest, load_split
    from phish_triage.service.scanner import Scanner

    load_split(DEPLOYED_SPLIT)  # stops if the `random` test emails are in its training data
    return Scanner(latest(split=DEPLOYED_SPLIT), threads=4)


def score(scanner, record: dict) -> dict:
    """The cascade's verdict and DistilBERT's own for one email, and whether the models read the hidden paragraph."""
    from phish_triage.models.baselines import email_text

    text = email_text(record, scanner.reader)
    result = scanner.scan_record(record)
    distilbert = result.score if result.stage == "distilbert" else float(scanner._distilbert.score([text])[0])
    return {
        "verdict": result.verdict,
        "stage": result.stage,
        "distilbert_phish": distilbert > scanner.config["distilbert_threshold"],
        "hidden_read": HARMLESS[:40] in text,
    }


def summarize(scores: list[dict], clean: list[dict] | None = None) -> dict:
    n = len(scores)
    verdicts = Counter(s["verdict"] for s in scores)
    out = {
        "emails": n,
        "flagged": verdicts["phish"],
        "recall": verdicts["phish"] / n,
        "review": verdicts["review"],
        "decided_by_stage_1": sum(s["stage"] == "stacked" for s in scores),
        "distilbert_recall": sum(s["distilbert_phish"] for s in scores) / n,
    }
    if clean is not None:  # the same emails: flagged clean, not flagged once attacked
        lost = [c["verdict"] == "phish" and s["verdict"] != "phish" for c, s in zip(clean, scores, strict=True)]
        out["lost"] = sum(lost)
        if any(s.get("hidden_read") for s in scores):
            out["hidden_read"] = sum(bool(s.get("hidden_read")) for s in scores)
            out["lost_with_hidden_read"] = sum(
                x and bool(s.get("hidden_read")) for x, s in zip(lost, scores, strict=True)
            )
    return out


def public_test_phish() -> list[dict]:
    from phish_triage.data.records import MASKED_RECORDS, read_records
    from phish_triage.data.splits import SPLITS_DIR

    splits = json.loads((SPLITS_DIR / "splits.json").read_text())
    records = read_records(MASKED_RECORDS, set(splits["random"]["test"]))
    return [records[i] for i in sorted(records) if records[i]["label"] == "phish"]


def evaluate_cascade(scanner, public: list[dict], greco: list[dict], log=print) -> dict:
    sets = {}
    clean = None
    for name, attack in ATTACKS.items():
        scores = [score(scanner, attack(r)) for r in public]
        clean = scores if name == "clean" else clean
        sets[name] = summarize(scores, None if name == "clean" else clean)
        log(f"{name}: recall {sets[name]['recall']:.4f}")
    greco_phish = [score(scanner, r) for r in greco if r["label"] == "phish"]
    greco_other = [score(scanner, r) for r in greco if r["label"] != "phish"]
    return {
        "bundle": scanner.version,
        "public_phish": sets,
        "greco_llm_phish": summarize(greco_phish),
        "greco_legit_file": summarize(greco_other),
    }


# --- The analyst sample ---


def analyst_sample() -> list[str]:
    from phish_triage.data.records import MASKED_RECORDS, read_records
    from phish_triage.data.splits import SPLITS_DIR
    from phish_triage.evaluation.analyst_eval import EMAILS
    from phish_triage.models.llm_classifier import sample_ids

    splits = json.loads((SPLITS_DIR / "splits.json").read_text())
    labels = {i: r["label"] for i, r in read_records(MASKED_RECORDS, set(splits["random"]["test"])).items()}
    phish = sorted(i for i in sample_ids(splits, EMAILS, labels) if labels[i] == "phish")
    return sorted(random.Random(SEED).sample(phish, ANALYST_EMAILS))


def build_analyst(scanner):
    """(request params by custom id, what each id means)."""
    from phish_triage.data.records import MASKED_RECORDS, read_analyst_view, read_records
    from phish_triage.features.domains import default_ranks
    from phish_triage.features.extract import extract
    from phish_triage.features.sender import check_sender
    from phish_triage.service import analyst

    ids = analyst_sample()
    records, views = read_records(MASKED_RECORDS, set(ids)), read_analyst_view(set(ids))
    ranks = default_ranks()
    params, meaning = {}, {}
    for email_id in ids:
        for name in ANALYST_ATTACKS:
            record, view = ATTACKS[name](records[email_id]), ATTACKS[name](views[email_id])
            result = scanner.scan_record(record)
            a = analyst.render(
                view,
                reader=scanner.reader,
                classifier_score=result.score,
                classifier_phish=result.cascade_phish,
                sender=check_sender(record, ranks),
                signals=analyst.signals_from_features(extract(record, ranks)),
            )
            custom_id = f"{email_id}-{name}"
            params[custom_id] = analyst.request_params(a)
            review = result.verdict == "review"
            meaning[custom_id] = {"attack": name, "flagged": result.cascade_phish, "review": review, "_input": a}
    return params, meaning


def evaluate_analyst(responses: dict, meaning: dict) -> dict:
    from phish_triage.service import analyst

    by_attack: dict = {name: {"emails": 0, "verdicts": Counter(), "suggestions": Counter()} for name in ANALYST_ATTACKS}
    invalid = 0
    for custom_id, m in meaning.items():
        raw = responses.get(custom_id, {})
        text = None if raw.get("error") else raw.get("text")
        r = analyst.finish(
            text,
            m["_input"],
            m["flagged"],
            refused=raw.get("stop_reason") == "refusal",
            cut_off=raw.get("error") == "max_tokens",
            classifier_review=m.get("review", False),
        )
        invalid += not r.schema_valid
        row = by_attack[m["attack"]]
        row["emails"] += 1
        row["verdicts"][r.verdict] += 1
        row["suggestions"][r.output.verdict_suggestion if r.output else "no valid answer"] += 1
    return {
        "prompt_version": analyst.PROMPT_VERSION,
        "llm_model": analyst.MODEL,
        "requests": len(meaning),
        "schema_valid_rate": (len(meaning) - invalid) / len(meaning),
        "by_attack": {
            k: {"emails": v["emails"], "verdicts": dict(v["verdicts"]), "suggestions": dict(v["suggestions"])}
            for k, v in by_attack.items()
        },
    }


# --- The report ---


def _pct(x: float) -> str:
    return f"{x:.1%}"


def _counts(counts: dict) -> str:
    order = ("phish", "suspicious", "needs_human_review", "likely_safe", "safe", "no valid answer")
    return ", ".join(
        f"{k.replace('_', ' ')} {counts[k]}" for k in sorted(counts, key=lambda k: (order + (k,)).index(k))
    )


def _findings(p: dict) -> list[str]:
    """What the table shows, written from its numbers."""
    clean, tricks = p["clean"], [f"hidden_html_{t}" for t in HIDING if t != "display_none"]
    control = p["hidden_html_display_none"]
    read, control_read, lost_read = (
        p[tricks[0]].get("hidden_read", 0),
        control.get("hidden_read", 0),
        control.get("lost_with_hidden_read", 0),
    )
    out = []
    if len({json.dumps(p[k], sort_keys=True) for k in tricks}) == 1:
        out.append(
            f"The three hiding tricks give the same numbers because the visible-text reader misses all three: the "
            f"models read the hidden paragraph in {read:,} of {clean['emails']:,} emails, "
            "the same text each time."
        )
    out.append(
        f"The control (inline `display:none`, which the reader drops) still lost {control['lost']}. The models read "
        f"its hidden paragraph in {control_read} emails, {lost_read} of the lost "
        "ones: HTML-only emails that show fewer than 5 visible words, where the models fall back to the parser's "
        "plain text, and that text keeps hidden elements."
    )
    if (end := p.get("hidden_html_style_class_at_end")) is not None:
        start = p["hidden_html_style_class"]
        out.append(
            "Most of the loss is DistilBERT's reading window, the first 512 tokens, which the hidden paragraph fills. "
            "Put at the end of the body instead (a check added after the first run, to explain it), the paragraph is "
            f"read in {end.get('hidden_read', 0):,} emails (in the others the models don't read that part of the "
            f"email) and {end.get('lost_with_hidden_read', 0):,} of them are lost, "
            f"against {start.get('lost_with_hidden_read', 0):,} of {start.get('hidden_read', 0):,} at the top."
        )
    if p["lookalike_letters"]["recall"] > clean["recall"]:
        out.append(
            "Look-alike letters made the phishing easier to catch, not harder: "
            f"{_pct(p['lookalike_letters']['recall'])} against {_pct(clean['recall'])} clean."
        )
    return [" ".join(out), ""]


def to_markdown(c: dict, a: dict | None) -> str:
    p = c["public_phish"]
    rows = [
        f"| {NAMES[k]} | {_pct(v['recall'])} ({v['flagged']:,} of {v['emails']:,}) | "
        f"{v.get('lost', '—')} | {v.get('hidden_read', '—')} | {v['review']} | "
        f"{_pct(v['decided_by_stage_1'] / v['emails'])} | {_pct(v['distilbert_recall'])} |"
        for k, v in p.items()
    ]
    g, gl = c["greco_llm_phish"], c["greco_legit_file"]
    lines = [
        "# Robustness: evasion tricks and LLM-written phishing",
        "",
        f"Generated by `make robustness`. The bundle `{c['bundle']}`, in service when this ran, one email at a time, "
        "as the service runs it. The attacks were set before the first run (`evaluation/robustness.py`); none was "
        "tuned on the results.",
        "",
        f"## The public test's phishing ({p['clean']['emails']:,} emails), attacked",
        "",
        "| Attack | Flagged (recall) | Lost (flagged clean, not attacked) | Models read the hidden paragraph "
        "| Sent to review | Decided by stage 1 | DistilBERT alone |",
        "|---|---:|---:|---:|---:|---:|---:|",
        *rows,
        "",
        *_findings(p),
        "*Lost* counts the same emails, clean and attacked. *DistilBERT alone*: its verdict on every email at its "
        "threshold, including the ones stage 1 decided. *Sent to review* is the little-text rule (an unflagged email "
        "with almost no words goes to a person).",
        "",
        "## LLM-written phishing (Greco et al.)",
        "",
        "| | Emails | Flagged | Decided by stage 1 | DistilBERT alone |",
        "|---|---:|---:|---:|---:|",
        f"| LLM-written phishing | {g['emails']:,} | {_pct(g['recall'])} ({g['flagged']:,}) | "
        f"{_pct(g['decided_by_stage_1'] / g['emails'])} | {_pct(g['distilbert_recall'])} |",
        f'| Their "legitimate" file (not usable as legitimate, see below) | {gl["emails"]:,} | '
        f"{_pct(gl['recall'])} ({gl['flagged']:,}) | {_pct(gl['decided_by_stage_1'] / gl['emails'])} | "
        f"{_pct(gl['distilbert_recall'])} |",
        "",
        "Each is the body text alone, so every one has the same made-up sender, no subject and no sender "
        "authentication: only the text differs. The human-written half of the dataset is not used, because it "
        'overlaps my training data (Nazario\'s phishing; CEAS, SpamAssassin and openSUSE mail). The "legitimate" '
        "file can't be used as legitimate mail: its label column says phishing on every row, and 316 of its 1,000 "
        "emails ask the reader to verify an account or claim something at a made-up link. So it gives no false-alarm "
        "number.",
        "",
    ]
    lines += ["## The analyst on a sample", ""]
    if a is None:
        lines += ["Not run yet (`make robustness-analyst`, costs money).", ""]
    else:
        lines += [
            f"{ANALYST_EMAILS} phishing emails from the fixed Claude sample, clean and under each attack, through the "
            f"defended analyst (prompt v{a['prompt_version']}, `{a['llm_model']}`) behind the deployed cascade: "
            f"{a['requests']} requests, {_pct(a['schema_valid_rate'])} valid answers.",
            "",
            "| Attack | Final verdict | Analyst's own suggestion |",
            "|---|---|---|",
            *[
                f"| {NAMES[k]} | {_counts(v['verdicts'])} | {_counts(v['suggestions'])} |"
                for k, v in a["by_attack"].items()
            ],
            "",
            "The analyst uses the same visible-text reader, so it gets the hidden paragraph too, but it reads the "
            "first 6,000 characters of the body and the list of link targets, not 512 tokens, so a harmless paragraph "
            "in front doesn't push the phishing out of what it reads. In the service it runs only when I ask for an "
            "explanation (`POST /v1/explain`); the scan's verdict is the cascade's, so this doesn't close the gap "
            "above.",
            "",
        ]
    return "\n".join(lines)


def write_report() -> str:
    c = json.loads((REPORTS_DIR / "robustness.json").read_text())
    path = REPORTS_DIR / "robustness_analyst.json"
    text = to_markdown(c, json.loads(path.read_text()) if path.exists() else None)
    (REPORTS_DIR / "robustness.md").write_text(text)
    return text


def main(argv: list[str] | None = None) -> int:
    from phish_triage.models import llm_batch
    from phish_triage.models.llm_classifier import max_llm_spend_usd, spent_usd
    from phish_triage.service import analyst

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("cascade", "plan", "run", "rescore"))
    parser.add_argument("--confirm", action="store_true", help="call the Claude API (costs money)")
    args = parser.parse_args(argv)
    scanner = deployed_scanner()
    REPORTS_DIR.mkdir(exist_ok=True)
    if args.command == "cascade":
        from phish_triage.data import greco

        result = evaluate_cascade(
            scanner, public_test_phish(), greco.records(), log=lambda m: print(m, file=sys.stderr)
        )
        (REPORTS_DIR / "robustness.json").write_text(json.dumps(result, indent=1) + "\n")
        print(write_report())
        return 0
    params, meaning = build_analyst(scanner)
    batch = f"robustness_v{analyst.PROMPT_VERSION}_{scanner.version}"
    if args.command == "plan":
        print(
            f"{len(params)} requests; worst case ${llm_batch.worst_case(params):.2f}; "
            f"spent so far ${spent_usd():.2f}; cap ${max_llm_spend_usd():.2f}"
        )
        return 0
    client = None
    if args.command == "rescore":  # re-apply the checks to the saved answers; no API calls
        llm_batch.check_fingerprint(batch, params)
        responses = llm_batch.load_saved(batch)
    elif not args.confirm:
        parser.error("this calls the Claude API and costs money; add --confirm")
    else:
        from phish_triage.models.llm_classifier import _client

        client = _client()
        responses = llm_batch.run(batch, params, client)
    valid = lambda raw: analyst.parse_answer(raw) is not None  # noqa: E731
    responses, retried = llm_batch.retry_invalid(batch, params, responses, valid, client)
    result = evaluate_analyst(responses, meaning) | {"retried": retried}
    (REPORTS_DIR / "robustness_analyst.json").write_text(json.dumps(result, indent=1) + "\n")
    print(write_report())
    print(f"total spent so far ${spent_usd():.2f} of ${max_llm_spend_usd():.2f}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
