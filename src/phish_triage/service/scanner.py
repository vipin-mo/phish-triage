"""One email in, one decision out: the deployed cascade, as the service runs it.

1. Parse the raw email and mask it exactly as the training data was (`data/mask.py`), so the models see the same
   kind of input they learned from. The recipient's own address is masked too.
2. Stage 1, the stacked model, decides when it is sure (the cutoffs chosen on validation, `evaluation/cascade.py`).
3. Otherwise DistilBERT (ONNX fp32) decides, with its validation threshold for 1% false alarms.
4. An email the cascade marks safe that has images or attachments but almost no visible words goes to review
   instead (`triage.too_little_text`): the text models had nothing to judge.

The verdict is `phish`, `safe` or `review`. Nothing here opens a URL, stores the email or calls an LLM.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import numpy as np

from phish_triage.service.bundle import verify

Verdict = Literal["phish", "safe", "review"]
log = logging.getLogger("phish_triage.scanner")
# Bump when the rules around the models change (triage, the sender check, masking, signals): stored verdicts carry
# it, so an email seen before is scanned again, as after a new model. 2: the forged lower Authentication-Results
# warning survives masking. 3: each verdict carries the threshold its score is compared with.
RULES_VERSION = 3


class FastTokenizer:
    """DistilBERT's tokenizer from its `tokenizer.json`, with the interface `transformer.encode` uses.

    The `tokenizers` library is the Rust core that `transformers` wraps, so the ids are the same without shipping
    transformers or torch to Lambda."""

    def __init__(self, path: Path):
        from tokenizers import Tokenizer

        self._tokenizer = Tokenizer.from_file(str(path))
        self._tokenizer.no_truncation()
        self._tokenizer.no_padding()
        self.cls_token_id = self._tokenizer.token_to_id("[CLS]")
        self.sep_token_id = self._tokenizer.token_to_id("[SEP]")
        self.pad_token_id = self._tokenizer.token_to_id("[PAD]")

    def __call__(self, texts: list[str], add_special_tokens: bool = False, truncation: bool = False) -> dict:
        encoded = self._tokenizer.encode_batch(texts, add_special_tokens=add_special_tokens)
        return {"input_ids": [e.ids for e in encoded]}


@dataclass(frozen=True)
class ScanResult:
    verdict: Verdict
    score: float  # probability of phishing from the stage that decided
    stage: Literal["stacked", "distilbert"]
    cascade_phish: bool  # the cascade's own decision, before the little-text rule
    little_text: bool
    signals: list[str] = field(default_factory=list)
    sender: dict = field(default_factory=dict)
    # The score is the deciding stage's, so it means something different per stage: phishing above this. DistilBERT's
    # threshold is 0.9964, so a score of 0.99 is still safe.
    phishing_above: float | None = None


class Scanner:
    def __init__(self, folder: Path, threads: int = 1):
        timings: dict[str, float] = {}
        started = last = time.perf_counter()

        def step(name: str) -> None:  # how long each part of a cold start takes, logged once per load
            nonlocal last
            now = time.perf_counter()
            timings[name] = round((now - last) * 1000)
            last = now
            log.info(json.dumps({"event": "scanner_loading", "step": name, "ms": timings[name]}))

        import joblib

        from phish_triage.features.domains import DomainRanks
        from phish_triage.models.transformer import OnnxClassifier

        step("imports_ms")
        self.config = verify(folder)
        self.version: str = self.config["version"]
        self.rules_version = RULES_VERSION
        step("verify_ms")
        models = joblib.load(folder / "stacked.joblib")
        self._tfidf, self._lr = models["text"].named_steps["tfidf"], models["text"].named_steps["lr"]
        self._stacked = models["stacked"]
        step("stacked_ms")
        self._ranks = DomainRanks.load_saved(folder / "domain_ranks.json")
        step("domain_list_ms")
        self._distilbert = OnnxClassifier(
            folder / "distilbert.onnx",
            tokenizer=FastTokenizer(folder / "tokenizer.json"),
            strategy=self.config["distilbert_strategy"],
            threads=threads,
        )
        step("distilbert_ms")
        timings["total_ms"] = round((time.perf_counter() - started) * 1000)
        log.info(json.dumps({"event": "scanner_loaded", "version": self.version, **timings}))

    @property
    def ranks(self):
        """The domain-popularity table, for the explanation step's sender check."""
        return self._ranks

    def scan(self, raw: bytes) -> ScanResult:
        from phish_triage.data.mask import mask_record
        from phish_triage.data.parse import parse_email

        record = parse_email(raw, source="live", label="unknown", origin="api").to_dict()
        return self.scan_record(mask_record(record))

    def scan_record(self, record: dict) -> ScanResult:
        """A masked record (`data/mask.py`), as in training."""
        from phish_triage.evaluation.cascade import Cutoffs, decide
        from phish_triage.features.extract import FEATURE_NAMES, extract
        from phish_triage.features.sender import check_sender, warning_sentence
        from phish_triage.models.baselines import email_text
        from phish_triage.service.analyst import signals_from_features
        from phish_triage.service.triage import LITTLE_TEXT_WORDS, too_little_text

        text = email_text(record)
        features = extract(record, self._ranks)
        row = np.array([[features[name] for name in FEATURE_NAMES]], dtype=float)
        text_score = self._lr.predict_proba(self._tfidf.transform([text]))[:, 1]
        stacked = float(self._stacked.predict_proba(np.column_stack([row, text_score]))[0, 1])
        cut = self.config["stage1_cutoffs"]
        decision = int(decide(np.array([stacked]), Cutoffs(cut["low"], cut["high"]))[0])
        if decision >= 0:
            stage, score, phish, above = "stacked", stacked, bool(decision), cut["high"]
        else:
            score = float(self._distilbert.score([text])[0])
            above = self.config["distilbert_threshold"]
            stage, phish = "distilbert", score > above
        little = too_little_text(record, self.config.get("little_text_words", LITTLE_TEXT_WORDS))
        verdict: Verdict = "phish" if phish else ("review" if little else "safe")
        sender = check_sender(record, self._ranks)
        return ScanResult(
            verdict=verdict,
            score=score,
            stage=stage,
            cascade_phish=phish,
            little_text=little,
            signals=signals_from_features(features),
            # The warnings name the sender's domains; the verdict is stored, so only their kind is kept.
            sender={"verdict": sender.verdict, "warnings": sorted({warning_sentence(w) for w in sender.warnings})},
            phishing_above=above,
        )
