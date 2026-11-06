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


CLIENT_RETRIES = 1  # the Anthropic client's own retry of a failed request (`anthropic_client`)


def worst_case_microusd(model: str = analyst.MODEL) -> int:
    """The most one explanation can cost: two calls (the schema retry), each tried up to 1 + CLIENT_RETRIES times
    (a request that timed out may still have been billed), each with the largest prompt the analyst builds (its body,
    header, link and attachment caps, applied after normalizing, the system prompt, about 3 characters a token) and
    the full output allowance. Reserved from the day's budget before the call, so calls running at once can't
    overshoot it."""
    from phish_triage.models.llm_classifier import PRICE_PER_MTOK

    prompt_chars = (
        len(analyst.SYSTEM_DEFENDED)
        + analyst.MAX_BODY_CHARS
        + analyst.MAX_FIELD_CHARS * (4 + analyst.MAX_LINKS + analyst.MAX_ATTACHMENTS)
        + 2_000  # the signals, tags and notes around the email
    )
    input_rate, output_rate = PRICE_PER_MTOK[model]
    per_call = (prompt_chars / 3 * input_rate + analyst.MAX_OUTPUT_TOKENS * output_rate) / 1e6
    return round(2 * (1 + CLIENT_RETRIES) * per_call * 1e6) + 1


class Explainer:
    def __init__(self, client, model: str = analyst.MODEL):
        self.client = client
        self.model = model

    def explain(self, raw: bytes, verdict: dict, ranks=None, reader: int = 1) -> Explanation:
        """`verdict`: the scan's stored verdict for the same email (`/v1/scan`'s answer); `reader`: the bundle's."""
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
            reader=reader,
        )
        params = analyst.request_params(a, self.model)
        cost, answer, reasons, content_failure = 0.0, None, [], False
        try:
            for _ in range(2):  # an answer that doesn't match the schema is asked for once more; a refusal isn't
                message = self.client.messages.create(**params, timeout=CALL_TIMEOUT_S)
                cost += cost_usd(self.model, message.usage, batch=False)
                answer = answer_of(message)
                if not needs_retry(answer, _valid):
                    break
                content_failure = True  # this answer didn't match the schema: the email may have caused it
        except Exception as exc:  # noqa: BLE001 - an outage or a timeout, unless the request itself was rejected
            # A 4xx other than auth and rate limits (a prompt too long, content the API won't take) is caused by the
            # email, so an attacker could use it to switch the analyst off: it counts like a refusal.
            status = getattr(exc, "status_code", None)
            content_failure = content_failure or (
                status is not None and 400 <= status < 500 and status not in (401, 403, 429)
            )
            answer, reasons = None, [f"the analyst could not be reached ({type(exc).__name__})"]
        result = analyst.finish(
            None if answer is None or answer.get("error") == "max_tokens" else answer.get("text"),
            a,
            flagged,
            refused=bool(answer) and answer.get("stop_reason") == "refusal",
            cut_off=bool(answer) and answer.get("error") == "max_tokens",
            classifier_review=verdict["verdict"] == "review",
            content_failure=content_failure and answer is None,
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
    return anthropic.Anthropic(api_key=secret["SecretString"].strip(), max_retries=CLIENT_RETRIES)
