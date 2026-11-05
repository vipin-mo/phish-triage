"""Do the explanations point at the words that drive the score? (reports/explanations.md)

    python -m phish_triage.evaluation.explanations     # $0, local; public test emails only

A deletion test on the deployed bundle's own models, reading as they read (its reader). For 300 public-test phishing
emails a model flags, remove the top 1, 3, 5 or 10 words an explanation picks, score the email again, and compare with
removing as many random words from the same pool (5 draws). A faithful explanation's words move the score much more
than random ones. A word is a whitespace token, matched without case or surrounding punctuation; removing it removes
every occurrence.

- **Stage 1's text model** (TF-IDF + logistic regression, the bundle's `text` model): LIME (`lime`, 500 samples). The
  reference is occlusion, each word's own effect on the score when it alone is removed, which is what an explanation
  can at best pick one word at a time. Pool: every word of the email.
- **DistilBERT**: Integrated Gradients (`captum`, 32 steps from an all-[PAD] baseline, on the word embeddings, of the
  phishing log-odds), token attributions summed per word. Pool: the words inside its 512 tokens. The deletions are
  scored with the bundle's ONNX model; the gradients come from the same weights in PyTorch.
"""

from __future__ import annotations

import json
import random
import re
import string
import sys
from pathlib import Path

import numpy as np

REPORTS_DIR = Path("reports")
EMAILS = 300
KS = (1, 3, 5, 10)
RANDOM_DRAWS = 5
LIME_SAMPLES = 500
IG_STEPS = 32
SEED = 20261107
LR_THRESHOLD = 0.5  # the text model is one input of stage 1, with no threshold of its own
_TOKEN = re.compile(r"\S+")


def key(token: str) -> str:
    return token.lower().strip(string.punctuation)


def words_of(text: str) -> list[str]:
    """The distinct words of `text`, in first-seen order."""
    return list(dict.fromkeys(k for t in _TOKEN.findall(text) if (k := key(t))))


def remove(text: str, words: set[str]) -> str:
    return _TOKEN.sub(lambda m: "" if key(m.group()) in words else m.group(), text)


def deletion(score, texts: list[str], ranked: list[list[str]], pools: list[list[str]], threshold: float) -> dict:
    """For each k: the mean score drop and the share that falls to the threshold or below, for the explanation's
    top-k words and for k random words from the same pool."""
    base = score(texts)
    rng = random.Random(SEED)
    out = {}
    for k in KS:
        top = score([remove(t, set(r[:k])) for t, r in zip(texts, ranked, strict=True)])
        draws = [
            score([remove(t, set(rng.sample(p, min(k, len(p))))) for t, p in zip(texts, pools, strict=True)])
            for _ in range(RANDOM_DRAWS)
        ]
        rand = np.mean(draws, axis=0)
        out[str(k)] = {
            "explanation_drop": float(np.mean(base - top)),
            "random_drop": float(np.mean(base - rand)),
            "explanation_below": float(np.mean(top <= threshold)),
            "random_below": float(np.mean([np.mean(d <= threshold) for d in draws])),
        }
    return out


# --- Stage 1's text model ---


def lime_ranking(predict, text: str) -> list[str]:
    from lime.lime_text import LimeTextExplainer

    explainer = LimeTextExplainer(class_names=["legit", "phish"], split_expression=r"\s+", bow=True, random_state=SEED)
    found = explainer.explain_instance(text, predict, num_features=max(KS), num_samples=LIME_SAMPLES, labels=(1,))
    ranked = [key(w) for w, weight in sorted(found.as_list(label=1), key=lambda x: -x[1]) if weight > 0]
    return list(dict.fromkeys(w for w in ranked if w))


def occlusion_ranking(score, text: str) -> list[str]:
    words = words_of(text)
    if not words:
        return []
    drops = score([text]) - score([remove(text, {w}) for w in words])
    return [w for w, d in sorted(zip(words, drops, strict=True), key=lambda x: -x[1]) if d > 0][: max(KS)]


# --- DistilBERT ---


def window_words(tokenizer, text: str, budget: int = 510) -> tuple[list[int], list[int | None]]:
    """The head strategy's token ids (`transformer.encode`) and, for each, the index of the whitespace token it
    falls in (None for [CLS] and [SEP])."""
    spans = [m.span() for m in _TOKEN.finditer(text)]
    enc = tokenizer(text, add_special_tokens=False, truncation=False, return_offsets_mapping=True)
    ids, offsets = enc["input_ids"][:budget], enc["offset_mapping"][:budget]
    starts = [s for s, _ in spans]
    owner = []
    for start, _ in offsets:
        i = int(np.searchsorted(starts, start, side="right")) - 1
        owner.append(i if i >= 0 and spans[i][0] <= start < spans[i][1] else None)
    return [tokenizer.cls_token_id, *ids, tokenizer.sep_token_id], [None, *owner, None]


def ig_ranking(model, tokenizer, text: str, device) -> tuple[list[str], list[str]]:
    """(words ranked by summed attribution toward phishing, the words inside the window)."""
    import torch
    from captum.attr import LayerIntegratedGradients

    ids, owner = window_words(tokenizer, text)
    tokens = _TOKEN.findall(text)
    input_ids = torch.tensor([ids], device=device)
    baseline = torch.full_like(input_ids, tokenizer.pad_token_id)
    baseline[0, 0], baseline[0, -1] = tokenizer.cls_token_id, tokenizer.sep_token_id
    mask = torch.ones_like(input_ids)

    def log_odds(input_ids, mask):
        logits = model(input_ids=input_ids, attention_mask=mask).logits
        return logits[:, 1] - logits[:, 0]

    ig = LayerIntegratedGradients(log_odds, model.distilbert.embeddings.word_embeddings)
    attributions = ig.attribute(
        input_ids, baselines=baseline, additional_forward_args=(mask,), n_steps=IG_STEPS, internal_batch_size=8
    )
    per_token = attributions.sum(dim=-1)[0].detach().cpu().numpy()
    per_word: dict[str, float] = {}
    for value, i in zip(per_token, owner, strict=True):
        if i is not None and (k := key(tokens[i])):
            per_word[k] = per_word.get(k, 0.0) + float(value)
    ranked = [w for w, v in sorted(per_word.items(), key=lambda x: -x[1]) if v > 0][: max(KS)]
    return ranked, list(per_word)


def onnx_log_odds(onnx, texts: list[str]) -> np.ndarray:
    """DistilBERT's phishing log-odds from the ONNX model. Its probabilities sit near 1 for most flagged phishing, so
    removing words can lower its confidence a lot without moving the probability; the log-odds show it."""
    from phish_triage.models import transformer

    ids = transformer.encode(onnx.tokenizer, texts, onnx.strategy)
    out = np.empty(len(ids))
    for start in range(0, len(ids), 32):
        input_ids, mask = transformer.pad(ids[start : start + 32], onnx.tokenizer.pad_token_id)
        logits = onnx.session.run(["logits"], {"input_ids": input_ids, "attention_mask": mask})[0]
        out[start : start + 32] = logits[:, 1] - logits[:, 0]
    return out


def torch_log_odds(model, tokenizer, texts: list[str]) -> np.ndarray:
    import torch

    from phish_triage.models import transformer

    out = []
    with torch.no_grad():
        for ids in transformer.encode(tokenizer, texts):
            logits = model(input_ids=torch.tensor([ids], device=next(model.parameters()).device)).logits[0]
            out.append(float(logits[1] - logits[0]))
    return np.array(out)


# --- The run ---


def flagged_sample(scores: np.ndarray, texts: list[str], threshold: float) -> list[int]:
    flagged = [i for i, s in enumerate(scores) if s > threshold and words_of(texts[i])]
    return sorted(random.Random(SEED).sample(flagged, min(EMAILS, len(flagged))))


def run() -> dict:
    import joblib
    from transformers import AutoModelForSequenceClassification

    from phish_triage.data.records import MASKED_RECORDS, read_records
    from phish_triage.data.splits import SPLITS_DIR
    from phish_triage.models import transformer
    from phish_triage.models.baselines import email_text
    from phish_triage.service.bundle import DEPLOYED_SPLIT, SOURCES, latest, verify

    folder = latest(split=DEPLOYED_SPLIT)
    config = verify(folder)
    reader = config.get("reader", 1)
    splits = json.loads((SPLITS_DIR / "splits.json").read_text())
    records = read_records(MASKED_RECORDS, set(splits["random"]["test"]))
    texts = [email_text(records[i], reader) for i in sorted(records) if records[i]["label"] == "phish"]
    result: dict = {"bundle": config["version"], "reader": reader, "emails": EMAILS}

    text_model = joblib.load(folder / "stacked.joblib")["text"]
    lr = lambda batch: text_model.predict_proba(batch)[:, 1]  # noqa: E731
    chosen = [texts[i] for i in flagged_sample(lr(texts), texts, LR_THRESHOLD)]
    pools = [words_of(t) for t in chosen]
    lime = [lime_ranking(text_model.predict_proba, t) for t in chosen]
    print("lime: done", file=sys.stderr)
    occlusion = [occlusion_ranking(lr, t) for t in chosen]
    result["text_model"] = {
        "threshold": LR_THRESHOLD,
        "lime": deletion(lr, chosen, lime, pools, LR_THRESHOLD),
        "occlusion": deletion(lr, chosen, occlusion, pools, LR_THRESHOLD),
    }
    print("text model: done", file=sys.stderr)

    onnx = transformer.OnnxClassifier(folder / "distilbert.onnx", threads=4)
    threshold = config["distilbert_threshold"]
    log_odds = lambda batch: onnx_log_odds(onnx, batch)  # noqa: E731
    threshold_log_odds = float(np.log(threshold / (1 - threshold)))
    chosen = [texts[i] for i in flagged_sample(log_odds(texts), texts, threshold_log_odds)]
    source = SOURCES[DEPLOYED_SPLIT][0] / "pytorch"
    device = transformer.device()
    model = AutoModelForSequenceClassification.from_pretrained(source).to(device).eval()
    tokenizer = transformer.load_tokenizer()
    ranked, pools = zip(*(ig_ranking(model, tokenizer, t, device) for t in chosen), strict=True)
    result["distilbert"] = {
        "threshold": threshold,
        "threshold_log_odds": threshold_log_odds,
        "torch_onnx_max_log_odds_difference": float(
            np.max(np.abs(torch_log_odds(model, tokenizer, chosen) - log_odds(chosen)))
        ),
        "integrated_gradients": deletion(log_odds, chosen, list(ranked), list(pools), threshold_log_odds),
    }
    return result


def to_markdown(r: dict) -> str:
    def table(rows: dict[str, dict], unit: str = "score drop") -> list[str]:
        out = [
            "| Words removed | "
            + " | ".join(f"{name}: {unit} | {name}: falls to the threshold" for name in rows)
            + f" | Random: {unit} | Random: falls to the threshold |",
            "|---:|" + "---:|---:|" * (len(rows) + 1),
        ]
        first = next(iter(rows.values()))
        for k in first:
            cells = [f"{v[k]['explanation_drop']:.3f} | {v[k]['explanation_below']:.0%}" for v in rows.values()]
            out.append(
                f"| {k} | " + " | ".join(cells) + f" | {first[k]['random_drop']:.3f} | {first[k]['random_below']:.0%} |"
            )
        return out

    t, d = r["text_model"], r["distilbert"]
    return "\n".join(
        [
            "# Do the explanations point at what drives the score?",
            "",
            f"Generated by `make explanations`. The deployed bundle `{r['bundle']}` (reader {r['reader']}), on "
            f"{r['emails']} public-test phishing emails each model flags. Remove the top 1, 3, 5 or 10 words an "
            "explanation picks and score again; random words from the same pool (5 draws) are the baseline. A "
            "word is a whitespace token, matched without case or surrounding punctuation.",
            "",
            f"## Stage 1's text model (TF-IDF + logistic regression; flagged = score above {t['threshold']})",
            "",
            "LIME (500 samples), and occlusion: each word's own effect when it alone is removed, the best an "
            "explanation can pick one word at a time.",
            "",
            *table({"LIME": t["lime"], "Occlusion": t["occlusion"]}),
            "",
            f"## DistilBERT (flagged = score above {d['threshold']:.4g}, log-odds {d['threshold_log_odds']:.2f})",
            "",
            "Integrated Gradients (32 steps from an all-[PAD] baseline, of the phishing log-odds), summed per word; "
            "only the words inside its 512 tokens. Its probabilities sit near 1 for most flagged phishing, so the "
            "drop is in log-odds. The deletions are scored with the bundle's ONNX model; PyTorch and ONNX log-odds "
            f"differ by at most {d['torch_onnx_max_log_odds_difference']:.1e} on these emails.",
            "",
            *table({"Integrated Gradients": d["integrated_gradients"]}, "log-odds drop"),
            "",
        ]
    )


def main() -> int:
    result = run()
    REPORTS_DIR.mkdir(exist_ok=True)
    (REPORTS_DIR / "explanations.json").write_text(json.dumps(result, indent=1) + "\n")
    text = to_markdown(result)
    (REPORTS_DIR / "explanations.md").write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
