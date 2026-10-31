"""Turn one raw RFC 822 email into the unified record every later stage uses.

Nothing here touches the network: URLs are collected as strings and never opened (threat model, rule 1).
Attachments are described (name, type, size) but their content is never written anywhere.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage, Message
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser

MAX_BODY_CHARS = 200_000  # longer bodies are cut and flagged; real phishing is far shorter
EARLIEST_PLAUSIBLE = datetime(1995, 1, 1, tzinfo=UTC)

URL_RE = re.compile(r"""(?:https?://|www\.)[^\s<>"'`{}|\\^\[\]]+""", re.IGNORECASE)
TRAILING_PUNCT = ".,;:!?)]}'\""


@dataclass
class Attachment:
    filename: str | None
    content_type: str
    size: int


@dataclass
class EmailRecord:
    id: str  # first 16 hex chars of the SHA-256 of the raw bytes
    source: str
    label: str  # "phish", "legit" or "spam"
    origin: str  # file (and member) the message came from, for tracing
    date: str | None  # ISO 8601, UTC
    date_from: str  # "received" (earliest hop), "date_header" or "none"
    headers: list[tuple[str, str]]
    subject: str
    text: str
    html: str
    urls: list[str]
    attachments: list[Attachment] = field(default_factory=list)
    raw_bytes: int = 0
    truncated: bool = False
    parse_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def parse_email(raw: bytes, *, source: str, label: str, origin: str, now: datetime | None = None) -> EmailRecord:
    errors: list[str] = []
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    headers = [(name, _decode_header(name, value, errors)) for name, value in msg.raw_items()]

    text_parts, html_parts, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        if _is_attachment(part):
            attachments.append(Attachment(_filename(part), content_type, _payload_size(part)))
        elif content_type == "text/plain":
            text_parts.append(_text_content(part, errors))
        elif content_type == "text/html":
            html_parts.append(_text_content(part, errors))

    text, html = "\n".join(text_parts), "\n".join(html_parts)
    truncated = len(text) > MAX_BODY_CHARS or len(html) > MAX_BODY_CHARS
    text, html = text[:MAX_BODY_CHARS], html[:MAX_BODY_CHARS]
    if not text and html:
        text = html_to_text(html)

    when, date_from = message_date(headers, now=now)
    return EmailRecord(
        id=hashlib.sha256(raw).hexdigest()[:16],
        source=source,
        label=label,
        origin=origin,
        date=when.isoformat() if when else None,
        date_from=date_from,
        headers=headers,
        subject=_header_value(headers, "subject") or "",
        text=text,
        html=html,
        urls=extract_urls(text, html),
        attachments=attachments,
        raw_bytes=len(raw),
        truncated=truncated,
        parse_errors=errors,
    )


def message_date(headers: list[tuple[str, str]], *, now: datetime | None = None) -> tuple[datetime | None, str]:
    """Date a message by its earliest Received hop, falling back to the Date header.

    The Date header is written by the sender and phishers forge it. Received headers are prepended by each
    server on the way, so the last one is the earliest hop. Implausible dates (before 1995, or in the future)
    are ignored.
    """
    latest_plausible = now or datetime.now(UTC)
    received = [value for name, value in headers if name.lower() == "received"]
    for value in reversed(received):
        when = _parse_date(value.rpartition(";")[2])
        if when and EARLIEST_PLAUSIBLE <= when <= latest_plausible:
            return when, "received"
    when = _parse_date(_header_value(headers, "date") or "")
    if when and EARLIEST_PLAUSIBLE <= when <= latest_plausible:
        return when, "date_header"
    return None, "none"


def extract_urls(text: str, html: str) -> list[str]:
    """URLs from link targets in the HTML and from the visible text, deduplicated, in first-seen order."""
    found = []
    if html:
        links = _LinkCollector()
        links.feed_safely(html)
        found.extend(links.hrefs)
        found.extend(URL_RE.findall(links.text()))
    found.extend(URL_RE.findall(text))
    seen, urls = set(), []
    for url in found:
        url = url.strip().rstrip(TRAILING_PUNCT)
        if url.lower().startswith(("http://", "https://", "www.")) and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def html_to_text(html: str) -> str:
    collector = _LinkCollector()
    collector.feed_safely(html)
    return collector.text()


class _LinkCollector(HTMLParser):
    """Collects visible text and href targets. Script and style contents are skipped."""

    SKIP = {"script", "style", "head", "title"}
    BLOCK = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "table"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []
        self._chunks: list[str] = []
        self._skip_depth = 0

    def feed_safely(self, html: str) -> None:
        try:
            self.feed(html)
            self.close()
        except (AssertionError, ValueError):  # malformed markup; keep what was parsed
            pass

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self.SKIP:
            self._skip_depth += 1
        elif tag in self.BLOCK:
            self._chunks.append("\n")
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.hrefs.append(href)

    def handle_endtag(self, tag: str) -> None:
        if tag in self.SKIP and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self._chunks.append(data)

    def text(self) -> str:
        joined = "".join(self._chunks)
        lines = (" ".join(line.split()) for line in joined.splitlines())
        return "\n".join(line for line in lines if line)


def _parse_date(value: str) -> datetime | None:
    value = value.strip()
    if not value:
        return None
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if when is None:
        return None
    return when.replace(tzinfo=UTC) if when.tzinfo is None else when.astimezone(UTC)


def _decode_header(name: str, raw_value: str, errors: list[str]) -> str:
    """Decode encoded words (=?utf-8?...?=) and unfold. Malformed headers fall back to the raw text."""
    try:
        return str(email.policy.default.header_fetch_parse(name, raw_value))
    except Exception as exc:  # noqa: BLE001 - malformed headers are common in phishing; keep going
        errors.append(f"header {name}: {type(exc).__name__}")
        return " ".join(raw_value.split())


def _header_value(headers: list[tuple[str, str]], name: str) -> str | None:
    return next((value for key, value in headers if key.lower() == name), None)


def _is_attachment(part: Message) -> bool:
    disposition = (part.get_content_disposition() or "").lower()
    return disposition == "attachment" or (
        part.get_filename() is not None and not part.get_content_type().startswith("text/")
    )


def _filename(part: Message) -> str | None:
    try:
        return part.get_filename()
    except Exception:  # noqa: BLE001
        return None


def _payload_size(part: Message) -> int:
    try:
        payload = part.get_payload(decode=True)
    except Exception:  # noqa: BLE001
        return 0
    return len(payload) if isinstance(payload, bytes) else 0


def _text_content(part: Message, errors: list[str]) -> str:
    if isinstance(part, EmailMessage):
        try:
            return part.get_content()
        except (LookupError, UnicodeError, AssertionError, ValueError) as exc:
            errors.append(f"{part.get_content_type()}: {type(exc).__name__}")
    payload = part.get_payload(decode=True)
    if not isinstance(payload, bytes):
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")
