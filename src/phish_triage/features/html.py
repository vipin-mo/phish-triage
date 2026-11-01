"""What an email's HTML contains: links with their visible text, forms, scripts and images. Nothing is fetched."""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser


@dataclass
class HtmlSummary:
    links: list[tuple[str, str]] = field(default_factory=list)  # (href, visible text)
    forms: int = 0
    password_inputs: int = 0
    scripts: int = 0
    images: int = 0


def summarize_html(html: str) -> HtmlSummary:
    parser = _Parser()
    try:
        parser.feed(html)
        parser.close()
    except (AssertionError, ValueError):  # malformed markup; keep what was parsed
        pass
    return parser.summary


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.summary = HtmlSummary()
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name: value or "" for name, value in attrs}
        if tag == "a":
            self._close_link()
            self._href = values.get("href", "").strip() or None
            self._text = []
        elif tag == "form":
            self.summary.forms += 1
        elif tag == "input" and values.get("type", "").lower() == "password":
            self.summary.password_inputs += 1
        elif tag == "script":
            self.summary.scripts += 1
        elif tag == "img":
            self.summary.images += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "a":
            self._close_link()

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def close(self) -> None:
        super().close()
        self._close_link()

    def _close_link(self) -> None:
        if self._href is not None:
            self.summary.links.append((self._href, " ".join("".join(self._text).split())))
        self._href = None
