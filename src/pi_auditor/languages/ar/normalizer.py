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

# A sequence such as "ت ج ا ه ل" is a common keyword-splitting evasion. Only
# sequences of at least three isolated Arabic letters are compacted; ordinary
# multi-letter Arabic words and whitespace remain unchanged.
_SPACED_ARABIC_LETTERS_RE = re.compile(
    r"(?<![\u0600-\u06FF])(?:[\u0621-\u064A][ \t\u00A0]+){2,}[\u0621-\u064A](?![\u0600-\u06FF])"
)

# Explicitly documented invisible controls plus non-format marks that can split
# Arabic tokens. All Unicode format controls are also treated as suspicious by
# _is_suspicious_invisible().
SUSPICIOUS_UNICODE_CODEPOINTS = frozenset(
    {
        0x00AD,  # SOFT HYPHEN
        0x034F,  # COMBINING GRAPHEME JOINER
        0x061C,  # ARABIC LETTER MARK
        0x180E,  # MONGOLIAN VOWEL SEPARATOR
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
        0x2061,  # FUNCTION APPLICATION
        0x2062,  # INVISIBLE TIMES
        0x2063,  # INVISIBLE SEPARATOR
        0x2064,  # INVISIBLE PLUS
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
    ord("ے"): "ي",  # Urdu yeh barree
    ord("ئ"): "ي",
    ord("ة"): "ه",
    ord("ک"): "ك",  # Persian kaf
    ord("ؤ"): "و",
}


def _is_suspicious_invisible(char: str) -> bool:
    """Return True for invisible controls useful for token splitting/reordering."""

    codepoint = ord(char)
    return (
        codepoint in SUSPICIOUS_UNICODE_CODEPOINTS
        or unicodedata.category(char) == "Cf"
        or 0xFE00 <= codepoint <= 0xFE0F  # variation selectors
        or 0xE0100 <= codepoint <= 0xE01EF  # supplementary variation selectors
    )


def _join_spaced_arabic_letters(match: re.Match) -> str:
    return re.sub(r"[ \t\u00A0]+", "", match.group(0))


def normalize_arabic(text: str) -> str:
    """Normalize Arabic text for security matching.

    Applies Unicode NFKC, removes Arabic diacritics and tatweel, normalizes
    common Arabic/Persian letter variants, strips invisible controls, and joins
    deliberately space-split Arabic keywords. Line breaks are preserved.
    """

    normalized = unicodedata.normalize("NFKC", text)
    normalized = _ARABIC_DIACRITICS_RE.sub("", normalized)
    normalized = "".join(char for char in normalized if not _is_suspicious_invisible(char))
    normalized = normalized.translate(_TRANSLATION_TABLE)
    return _SPACED_ARABIC_LETTERS_RE.sub(_join_spaced_arabic_letters, normalized)


def suspicious_unicode_lines(text: str) -> List[int]:
    """Return 1-based source lines containing suspicious invisible controls."""

    return [
        index
        for index, line in enumerate(text.splitlines(), start=1)
        if any(_is_suspicious_invisible(char) for char in line)
    ]
