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


# --- What a person actually sees (threat model, rule 5) -------------------------------------------------------

SKIPPED = frozenset({"script", "style", "head", "title", "template", "noscript"})
BLOCK = frozenset({"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "section", "td"})
VOID = frozenset(
    {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
)
NAMED = {
    "white": (255, 255, 255),
    "black": (0, 0, 0),
    "red": (255, 0, 0),
    "silver": (192, 192, 192),
    "gray": (128, 128, 128),
    "grey": (128, 128, 128),
    "whitesmoke": (245, 245, 245),
    "snow": (255, 250, 250),
}
MIN_CONTRAST = 1.5  # WCAG contrast ratio below this is unreadable (normal text needs 4.5)


@dataclass
class VisibleHtml:
    text: str  # what a reader sees
    hidden_text: str  # text a reader doesn't see but a model reading the raw HTML would
    hidden: dict[str, int] = field(default_factory=dict)  # technique -> count


def visible_html(html: str) -> VisibleHtml:
    """Split HTML into visible and hidden text. Hidden: comments, `display:none` / `visibility:hidden` / the `hidden`
    attribute, zero-size or transparent text, text the same colour as its background, and image alt text."""
    parser = _VisibilityParser()
    try:
        parser.feed(html)
        parser.close()
    except (AssertionError, ValueError):
        pass
    return parser.result()


def _style(attrs: dict[str, str]) -> dict[str, str]:
    declarations = {}
    for part in attrs.get("style", "").split(";"):
        name, _, value = part.partition(":")
        if value:
            declarations[name.strip().lower()] = value.strip().lower().replace(" ", "").removesuffix("!important")
    return declarations


def _number(value: str) -> float | None:
    digits = "".join(ch for ch in value if ch.isdigit() or ch == ".")
    try:
        return float(digits) if digits else None
    except ValueError:
        return None


def _hiding(tag: str, attrs: dict[str, str], background: str) -> tuple[str | None, str]:
    """(technique that hides this element or None, the background colour its children sit on)."""
    style = _style(attrs)
    bg = style.get("background-color") or style.get("background") or attrs.get("bgcolor", "").lower() or background
    if "hidden" in attrs or style.get("display") == "none" or style.get("visibility") == "hidden":
        return "css_hidden", bg
    size = _number(style.get("font-size", ""))
    opacity = _number(style.get("opacity", ""))
    if (size is not None and size <= 1) or (opacity is not None and opacity < 0.1):
        return "tiny_or_transparent", bg
    for dimension in ("max-height", "height", "width"):
        if _number(style.get(dimension, "x")) == 0 and style.get("overflow", "") == "hidden":
            return "tiny_or_transparent", bg
    colour = style.get("color") or (attrs.get("color", "").lower() if tag == "font" else "")
    if colour and (ratio := contrast(colour, bg)) is not None and ratio < MIN_CONTRAST:
        return "same_colour", bg
    return None, bg


def rgb(colour: str) -> tuple[int, int, int] | None:
    """#rgb, #rrggbb, rgb(r,g,b), rgba(...) or a few common names; None when unknown."""
    colour = colour.strip().lower().split()[0] if colour.strip() else ""
    if colour in NAMED:
        return NAMED[colour]
    if colour.startswith("#") and len(colour) in (4, 7):
        digits = colour[1:]
        if len(digits) == 3:
            digits = "".join(ch * 2 for ch in digits)
        try:
            return tuple(int(digits[i : i + 2], 16) for i in (0, 2, 4))  # type: ignore[return-value]
        except ValueError:
            return None
    if colour.startswith(("rgb(", "rgba(")):
        parts = colour[colour.index("(") + 1 : colour.rindex(")")].split(",")[:3] if ")" in colour else []
        try:
            values = tuple(int(float(v)) for v in parts)
        except ValueError:
            return None
        return values if len(values) == 3 else None  # type: ignore[return-value]
    return None


def contrast(foreground: str, background: str) -> float | None:
    """WCAG contrast ratio between two CSS colours (1 = identical, 21 = black on white)."""
    fg, bg = rgb(foreground), rgb(background or "#ffffff")
    if fg is None or bg is None:
        return None

    def luminance(c: tuple[int, int, int]) -> float:
        channels = [v / 255 for v in c]
        linear = [v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4 for v in channels]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    lighter, darker = sorted((luminance(fg), luminance(bg)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


MAX_DEPTH = 1_000  # deeper elements inherit their parent's state but aren't tracked (bounds work and memory)


class _VisibilityParser(HTMLParser):
    """Each stack entry carries its *effective* state (hidden by itself or by an ancestor), so looking it up is O(1);
    re-scanning the stack made 100,000 unclosed tags take 30 seconds."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, str | None, str]] = []  # (tag, effective hiding technique, background)
        self.visible: list[str] = []
        self.hidden_parts: list[str] = []
        self.hidden: dict[str, int] = {}

    def _state(self) -> tuple[str | None, str]:
        return (self.stack[-1][1], self.stack[-1][2]) if self.stack else (None, "#ffffff")

    def _count(self, technique: str) -> None:
        self.hidden[technique] = self.hidden.get(technique, 0) + 1

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): value or "" for name, value in attrs}
        inherited, background = self._state()
        if tag == "img" and values.get("alt", "").strip():
            self._count("alt_text")
            self.hidden_parts.append(values["alt"].strip())
        if tag in BLOCK and not inherited:
            self.visible.append("\n")
        if tag in VOID or len(self.stack) >= MAX_DEPTH:
            return
        technique = "skipped" if tag in SKIPPED else None
        if technique is None:
            technique, background = _hiding(tag, values, background)
            if technique and not inherited:
                self._count(technique)
        self.stack.append((tag, technique or inherited, background))  # the nearest hiding element decides

    def handle_endtag(self, tag: str) -> None:
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                return

    def handle_data(self, data: str) -> None:
        hidden, _ = self._state()
        if hidden is None:
            self.visible.append(data)
        elif hidden != "skipped" and data.strip():
            self.hidden_parts.append(data.strip())

    def handle_comment(self, data: str) -> None:
        if data.strip():
            self._count("comment")
            self.hidden_parts.append(data.strip())

    def result(self) -> VisibleHtml:
        lines = (" ".join(line.split()) for line in "".join(self.visible).splitlines())
        return VisibleHtml("\n".join(line for line in lines if line), "\n".join(self.hidden_parts), dict(self.hidden))
