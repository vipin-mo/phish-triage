from types import SimpleNamespace

import pytest

from phish_triage.models import llm_batch


class FakeClient:
    def __init__(self, text):
        self.calls, self.text = 0, text
        self.messages = self

    def create(self, **params):
        self.calls += 1
        usage = SimpleNamespace(input_tokens=100, output_tokens=50, cache_read_input_tokens=0)
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text=self.text)], stop_reason="end_turn", usage=usage
        )


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    spent = []
    monkeypatch.setattr(llm_batch, "LLM_DIR", tmp_path)
    monkeypatch.setattr(llm_batch, "record_spend", spent.append)
    monkeypatch.setattr(llm_batch, "check_budget", lambda *a: None)
    return spent


def test_an_invalid_answer_is_asked_for_once_more_and_a_refusal_is_not(ledger):
    params = {i: {"model": "claude-haiku-5-5"} for i in "abc"}
    responses = {
        "a": {"text": "good", "stop_reason": "end_turn", "error": None},
        "b": {"text": "too long", "stop_reason": "end_turn", "error": None},
        "c": {"text": None, "stop_reason": "refusal", "error": "refusal (bio)"},
    }
    valid = lambda raw: raw == "good"  # noqa: E731
    client = FakeClient("good")
    out, retried = llm_batch.retry_invalid("t", params, responses, valid, client)
    assert retried == 1 and client.calls == 1 and out["b"]["text"] == "good" and out["c"]["error"] == "refusal (bio)"
    assert len(ledger) == 1
    again, _ = llm_batch.retry_invalid("t", params, responses, valid, None)  # saved: no new call, no new cost
    assert again == out and client.calls == 1 and len(ledger) == 1


def test_a_needed_retry_without_a_client_stops(ledger):
    responses = {"b": {"text": "bad", "stop_reason": "end_turn", "error": None}}
    with pytest.raises(SystemExit):
        llm_batch.retry_invalid("u", {"b": {"model": "m"}}, responses, lambda raw: False, None)


def test_saved_answers_are_reused_only_for_the_same_requests(ledger):
    asked = {"a": {"model": "m", "messages": [{"content": "This request's tag id is 1a2b3c4d. <email-1a2b3c4d>"}]}}
    again = {"a": {"model": "m", "messages": [{"content": "This request's tag id is 99ff00aa. <email-99ff00aa>"}]}}
    assert llm_batch.fingerprint(asked) == llm_batch.fingerprint(again)  # only the random tag differs
    llm_batch.check_fingerprint("f", asked)
    llm_batch.check_fingerprint("f", again)
    with pytest.raises(SystemExit):
        llm_batch.check_fingerprint("f", {"a": {**asked["a"], "model": "another-model"}})
