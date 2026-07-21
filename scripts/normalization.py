"""Text normalization helpers used by the prompt-injection scanner.

The functions in this module are dependency-free and preserve newline counts so
that findings can still be mapped to the original source lines.
"""

import re
import unicodedata
from typing import List

# Arabic combining marks and Quranic annotation ranges commonly used to evade
# literal matching. Newlines are intentionally not included.
_ARABIC_DIACRITICS_RE = re.compile(
    "["
    "\u0610-\u061A"
    "\u064B-\u065F"
    "\u0670"
    "\u06D6-\u06DC"
    "\u06DF-\u06E4"
    "\u06E7-\u06E8"
    "\u06EA-\u06ED"
    "]"
)

# Invisible formatting characters that can split words or reverse their visual
# order during review. They are removed for matching, but reported separately.
SUSPICIOUS_UNICODE_CODEPOINTS = frozenset(
    {
        0x061C,  # ARABIC LETTER MARK
        0x200B,  # ZERO WIDTH SPACE
        0x200C,  # ZERO WIDTH NON-JOINER
        0x200D,  # ZERO WIDTH JOINER
        0x200E,  # LEFT-TO-RIGHT MARK
        0x200F,  # RIGHT-TO-LEFT MARK
        0x202A,  # LEFT-TO-RIGHT EMBEDDING
        0x202B,  # RIGHT-TO-LEFT EMBEDDING
        0x202C,  # POP DIRECTIONAL FORMATTING
        0x202D,  # LEFT-TO-RIGHT OVERRIDE
        0x202E,  # RIGHT-TO-LEFT OVERRIDE
        0x2060,  # WORD JOINER
        0x2066,  # LEFT-TO-RIGHT ISOLATE
        0x2067,  # RIGHT-TO-LEFT ISOLATE
        0x2068,  # FIRST STRONG ISOLATE
        0x2069,  # POP DIRECTIONAL ISOLATE
        0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BOM
    }
)

_TRANSLATION_TABLE = {
    ord("ـ"): None,  # tatweel
    ord("أ"): "ا",
    ord("إ"): "ا",
    ord("آ"): "ا",
    ord("ٱ"): "ا",
    ord("ى"): "ي",
    ord("ی"): "ي",  # Persian yeh
}
_TRANSLATION_TABLE.update({codepoint: None for codepoint in SUSPICIOUS_UNICODE_CODEPOINTS})


def normalize_arabic(text: str) -> str:
    """Normalize Arabic text for security matching.

    Applies Unicode NFKC, removes Arabic diacritics and tatweel, normalizes alef
    and yeh variants, and strips invisible direction/zero-width controls.
    Line breaks are preserved.
    """

    normalized = unicodedata.normalize("NFKC", text)
    normalized = _ARABIC_DIACRITICS_RE.sub("", normalized)
    return normalized.translate(_TRANSLATION_TABLE)


def suspicious_unicode_lines(text: str) -> List[int]:
    """Return 1-based source lines containing suspicious invisible controls."""

    return [
        index
        for index, line in enumerate(text.splitlines(), start=1)
        if any(ord(char) in SUSPICIOUS_UNICODE_CODEPOINTS for char in line)
    ]
