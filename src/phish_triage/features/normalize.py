"""Reader 2's text clean-up (Phase 7.2, the robustness defence): what the models read, written the plain way.

- Format characters (Unicode category Cf: zero-width spaces and joiners, the word joiner, text-direction marks, soft
  hyphens, byte-order marks) are removed; a reader doesn't see them, but they split words for a model.
- NFKC folds compatibility forms (fullwidth letters, ligatures) into the ordinary ones.
- In a word that mixes Latin letters with letters of another script, each letter that has a Latin look-alike (by the
  Unicode confusables data in `confusable_homoglyphs`) becomes that Latin letter: `pаypal` with a Cyrillic `а` reads
  as `paypal`. A word written wholly in another script, as in a Russian or Greek email, is left alone.
"""

from __future__ import annotations

import re
import unicodedata
from functools import lru_cache

_WORD = re.compile(r"[^\W\d_]+")


@lru_cache(maxsize=4096)
def _latin_twin(ch: str) -> str:
    from confusable_homoglyphs import confusables

    found = confusables.is_confusable(ch, preferred_aliases=["latin"], greedy=True) or []
    for entry in found:
        for glyph in entry.get("homoglyphs", []):
            if len(glyph["c"]) == 1 and glyph["c"].isascii() and glyph["c"].isalpha():
                return glyph["c"]
    return ch


@lru_cache(maxsize=4096)
def _script(ch: str) -> str:
    from confusable_homoglyphs import categories

    return categories.alias(ch)


def _fix_word(m: re.Match) -> str:
    word = m.group()
    if word.isascii():
        return word
    scripts = {_script(ch) for ch in word}
    if "LATIN" not in scripts or len(scripts) == 1:
        return word
    return "".join(ch if _script(ch) == "LATIN" else _latin_twin(ch) for ch in word)


def normalize_text(text: str) -> str:
    if text.isascii():
        return text
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    text = unicodedata.normalize("NFKC", text)
    return _WORD.sub(_fix_word, text)
