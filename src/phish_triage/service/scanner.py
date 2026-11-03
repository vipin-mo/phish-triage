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

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import numpy as np

from phish_triage.service.bundle import verify

Verdict = Literal["phish", "safe", "review"]


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


class Scanner:
    def __init__(self, folder: Path, threads: int = 1):
        import joblib

        from phish_triage.features.domains import DomainRanks
        from phish_triage.models.transformer import OnnxClassifier

        self.config = verify(folder)
        self.version: str = self.config["version"]
        models = joblib.load(folder / "stacked.joblib")
        self._tfidf, self._lr = models["text"].named_steps["tfidf"], models["text"].named_steps["lr"]
        self._stacked = models["stacked"]
        self._ranks = DomainRanks.load(folder / "tranco.csv")
        self._distilbert = OnnxClassifier(
            folder / "distilbert.onnx",
            tokenizer=FastTokenizer(folder / "tokenizer.json"),
            strategy=self.config["distilbert_strategy"],
            threads=threads,
        )

    def scan(self, raw: bytes) -> ScanResult:
        from phish_triage.data.mask import mask_record
        from phish_triage.data.parse import parse_email

        record = parse_email(raw, source="live", label="unknown", origin="api").to_dict()
        return self.scan_record(mask_record(record))

    def scan_record(self, record: dict) -> ScanResult:
        """A masked record (`data/mask.py`), as in training."""
        from phish_triage.evaluation.cascade import Cutoffs, decide
        from phish_triage.features.extract import FEATURE_NAMES, extract
        from phish_triage.features.sender import check_sender
        from phish_triage.models.baselines import email_text
        from phish_triage.service.analyst import signals_from_features
        from phish_triage.service.triage import too_little_text

        text = email_text(record)
        features = extract(record, self._ranks)
        row = np.array([[features[name] for name in FEATURE_NAMES]], dtype=float)
        text_score = self._lr.predict_proba(self._tfidf.transform([text]))[:, 1]
        stacked = float(self._stacked.predict_proba(np.column_stack([row, text_score]))[0, 1])
        cut = self.config["stage1_cutoffs"]
        decision = int(decide(np.array([stacked]), Cutoffs(cut["low"], cut["high"]))[0])
        if decision >= 0:
            stage, score, phish = "stacked", stacked, bool(decision)
        else:
            score = float(self._distilbert.score([text])[0])
            stage, phish = "distilbert", score > self.config["distilbert_threshold"]
        little = too_little_text(record)
        verdict: Verdict = "phish" if phish else ("review" if little else "safe")
        sender = check_sender(record, self._ranks)
        return ScanResult(
            verdict=verdict,
            score=score,
            stage=stage,
            cascade_phish=phish,
            little_text=little,
            signals=signals_from_features(features),
            sender={"verdict": sender.verdict, "warnings": list(sender.warnings)},
        )
