import json
from pathlib import Path
from types import SimpleNamespace

from phish_triage.service.explain import Explainer

FIXTURES = Path(__file__).parent / "fixtures"
GOOD = {
    "verdict_suggestion": "phish",
    "summary": "This email pretends to be a bank and asks you to confirm your password.",
    "indicators": [],
    "recommended_action": "block_and_report",
}
VERDICT = {"scan_id": "x" * 64, "verdict": "safe", "score": 0.1, "signals": []}


def _message(text: str | None, stop_reason: str = "end_turn"):
    usage = SimpleNamespace(input_tokens=1000, output_tokens=100, cache_read_input_tokens=0)
    content = [SimpleNamespace(type="text", text=text)] if text is not None else []
    return SimpleNamespace(content=content, stop_reason=stop_reason, stop_details=None, usage=usage)


class FakeClient:
    def __init__(self, *answers):
        self.answers, self.calls = list(answers), 0
        self.messages = self

    def create(self, **params):
        self.calls += 1
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


def _explain(*answers, verdict=VERDICT):
    client = FakeClient(*answers)
    result = Explainer(client).explain((FIXTURES / "clean_newsletter.eml").read_bytes(), verdict)
    return result, client


def test_the_explanation_raises_risk_and_is_asked_for_once_more_when_invalid():
    result, client = _explain(_message("not json"), _message(json.dumps(GOOD)))
    assert client.calls == 2 and result.body["verdict"] == "phish" and result.cost_usd > 0
    assert result.body["summary"] == GOOD["summary"] and result.body["scanner_verdict"] == "safe"


def test_a_refusal_is_not_retried_and_goes_to_a_person():
    result, client = _explain(_message(None, stop_reason="refusal"))
    assert client.calls == 1 and result.body["verdict"] == "needs_human_review"


def test_an_outage_keeps_the_scanners_verdict_and_says_why():
    result, _ = _explain(TimeoutError("slow"))
    assert result.body["verdict"] == "safe" and "could not be reached (TimeoutError)" in result.body["reasons"][0]
    flagged, _ = _explain(TimeoutError("slow"), verdict={**VERDICT, "verdict": "phish", "score": 0.999})
    assert flagged.body["verdict"] == "phish"
