"""What the service keeps: API keys (hashed), verdicts, feedback and a per-key request count. Never an email.

A verdict is stored under the SHA-256 of the email's bytes (the scan id), so the same email sent again returns the
same verdict without scanning it again, and feedback can name the scan it is about. A verdict from an older model
is replaced by a new scan, so a model that fixes a false alarm fixes it for emails already seen too; feedback
records which model's verdict it was about. The hash identifies an email but can't be turned back into it.

API keys are random 32-byte tokens, so a plain SHA-256 is enough to store them: there is nothing to guess, unlike
a password. `MemoryStore` is for tests and local runs; `store_dynamo.DynamoStore` is what runs on AWS.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Protocol

FEEDBACK_LABELS = ("correct", "false_alarm", "missed_phish")


def hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


def new_api_key() -> str:
    return "pt_" + secrets.token_urlsafe(32)


def scan_id(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class Store(Protocol):
    def key_owner(self, api_key: str) -> str | None: ...
    def allow(self, owner: str, per_minute: int) -> bool: ...
    def get_verdict(self, owner: str, scan: str) -> dict | None: ...
    def put_verdict(self, owner: str, scan: str, verdict: dict) -> None: ...
    def put_feedback(self, owner: str, scan: str, label: str, model_version: str | None = None) -> None: ...
    # the day's total after adding (UTC days); `day` (`today()`) settles on the day a reservation was made
    def add_today(self, counter: str, amount: int, day: int | None = None) -> int: ...


def today() -> int:
    """The UTC day number the daily counters are kept under."""
    return int(time.time() // 86_400)


@dataclass
class MemoryStore:
    keys: dict[str, str] = field(default_factory=dict)  # key hash -> owner
    verdicts: dict[tuple[str, str], dict] = field(default_factory=dict)
    feedback: list[dict] = field(default_factory=list)
    _counts: defaultdict[tuple[str, int], int] = field(default_factory=lambda: defaultdict(int))

    def add_key(self, owner: str) -> str:
        api_key = new_api_key()
        self.keys[hash_key(api_key)] = owner
        return api_key

    def key_owner(self, api_key: str) -> str | None:
        return self.keys.get(hash_key(api_key))

    def allow(self, owner: str, per_minute: int) -> bool:
        minute = int(time.time() // 60)
        self._counts[(owner, minute)] += 1
        return self._counts[(owner, minute)] <= per_minute

    def get_verdict(self, owner: str, scan: str) -> dict | None:
        return self.verdicts.get((owner, scan))

    def put_verdict(self, owner: str, scan: str, verdict: dict) -> None:
        self.verdicts[(owner, scan)] = verdict

    def add_today(self, counter: str, amount: int, day: int | None = None) -> int:
        day = today() if day is None else day
        self._counts[(f"day#{counter}", day)] += amount
        return self._counts[(f"day#{counter}", day)]

    def put_feedback(self, owner: str, scan: str, label: str, model_version: str | None = None) -> None:
        self.feedback.append(
            {"owner": owner, "scan_id": scan, "label": label, "model_version": model_version, "at": int(time.time())}
        )
