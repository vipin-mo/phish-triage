"""The explanation step, on demand: `POST /v1/explain` runs the defended analyst (`service/analyst.py`) on one email.

The add-on sends the email again when I click Explain, so nothing is kept for later: the email is in the request,
goes to Anthropic once (PII redacted, hidden text removed, between random tags) and the explanation goes back in
the response. Neither is stored or queued; only a per-key count and the day's spend are.

The final verdict follows the analyst's rules: raise only, a refusal or an answer that's cut off or still invalid
after asking once more sends an unflagged email to a person, and the scanner's "review" is a floor. If Anthropic
can't be reached (a timeout, an outage), the scanner's verdict stands and the reason says so.

The Anthropic key is read from AWS Secrets Manager on the first explanation of a cold start, never from the image
or an environment variable.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from phish_triage.service import analyst

CALL_TIMEOUT_S = 12  # API Gateway answers at 29 s: two calls (the retry) plus the scan must fit


@dataclass
class Explanation:
    body: dict  # what the API returns
    cost_usd: float


def _valid(raw: str | None) -> bool:
    return analyst.parse_answer(raw) is not None


class Explainer:
    def __init__(self, client, model: str = analyst.MODEL):
        self.client = client
        self.model = model

    def explain(self, raw: bytes, verdict: dict, ranks=None) -> Explanation:
        """`verdict`: the scan's stored verdict for the same email (`/v1/scan`'s answer)."""
        from phish_triage.data.mask import mask_record
        from phish_triage.data.parse import parse_email
        from phish_triage.features.sender import check_sender
        from phish_triage.models.llm_batch import answer_of, needs_retry
        from phish_triage.models.llm_classifier import cost_usd

        # The analyst sees the email masked like the training data, but with the sources' names kept (as in the
        # evaluations); `render` redacts personal data and refuses private datasets.
        record = mask_record(
            parse_email(raw, source="live", label="unknown", origin="api").to_dict(), source_names=False
        )
        flagged = verdict["verdict"] == "phish"
        a = analyst.render(
            record,
            classifier_score=verdict["score"],
            classifier_phish=flagged,
            sender=check_sender(record, ranks),
            signals=verdict.get("signals") or [],
        )
        params = analyst.request_params(a, self.model)
        cost, answer, reasons = 0.0, None, []
        try:
            for _ in range(2):  # an answer that doesn't match the schema is asked for once more; a refusal isn't
                message = self.client.messages.create(**params, timeout=CALL_TIMEOUT_S)
                cost += cost_usd(self.model, message.usage, batch=False)
                answer = answer_of(message)
                if not needs_retry(answer, _valid):
                    break
        except Exception as exc:  # noqa: BLE001 - an outage or timeout: the email didn't cause it
            answer, reasons = None, [f"the analyst could not be reached ({type(exc).__name__})"]
        result = analyst.finish(
            None if answer is None or answer.get("error") == "max_tokens" else answer.get("text"),
            a,
            flagged,
            refused=bool(answer) and answer.get("stop_reason") == "refusal",
            cut_off=bool(answer) and answer.get("error") == "max_tokens",
            classifier_review=verdict["verdict"] == "review",
        )
        output = result.output
        body = {
            "scan_id": verdict["scan_id"],
            "verdict": result.verdict,
            "scanner_verdict": verdict["verdict"],
            "summary": output.summary if output else None,
            "recommended_action": output.recommended_action if output else None,
            "indicators": [
                {"type": i.type, "evidence": analyst.shown_evidence(i, a), "why": i.why} for i in output.indicators
            ]
            if output
            else [],
            "reasons": reasons + result.reasons,
            "llm_model": self.model,
        }
        return Explanation(body, cost)


def anthropic_client():
    """The Anthropic client with the key from Secrets Manager (`PHISH_ANTHROPIC_SECRET`, set by infra/service)."""
    import anthropic
    import boto3

    secret = boto3.client("secretsmanager").get_secret_value(SecretId=os.environ["PHISH_ANTHROPIC_SECRET"])
    return anthropic.Anthropic(api_key=secret["SecretString"].strip(), max_retries=1)
