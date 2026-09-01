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


# Scripts whose typography legitimately uses ZWNJ/ZWJ and direction marks:
# Arabic (incl. Persian/Urdu), Hebrew, Syriac, Thaana, N'Ko and their
# presentation forms. Between letters of these scripts those characters are
# ordinary writing, not obfuscation.
_SHAPING_SCRIPT_RE = re.compile(
    "["
    "\u0590-\u05FF"  # Hebrew
    "\u0600-\u06FF"  # Arabic
    "\u0700-\u074F"  # Syriac
    "\u0750-\u077F"  # Arabic Supplement
    "\u07C0-\u07FF"  # N'Ko
    "\u08A0-\u08FF"  # Arabic Extended-A
    "\uFB50-\uFDFF"  # Arabic Presentation Forms-A
    "\uFE70-\uFEFF"  # Arabic Presentation Forms-B
    "]"
)

# Emoji bases, symbols, arrows, dingbats and pictographs live at U+2190 and
# above (❤ U+2764, ✅ U+2705, 👨 U+1F468, skin tones U+1F3FB, ...). A ZWJ or
# variation selector after one of these is an emoji sequence, not a hidden
# control. Nothing an LLM prompt legitimately needs sits below that line
# paired with a joiner/selector.
def _is_emoji_context(char: str) -> bool:
    return ord(char) >= 0x2190


# Letters where a glued-on variation selector has no typographic meaning.
_LATIN_CYRILLIC_GREEK_RE = re.compile("[A-Za-z\u00c0-\u024f\u0370-\u03ff\u0400-\u04ff]")


def _is_cjk(char: str) -> bool:
    cp = ord(char)
    return 0x3400 <= cp <= 0x4DBF or 0x4E00 <= cp <= 0x9FFF or 0xF900 <= cp <= 0xFAFF


def _suspicious_at(line: str, pos: int) -> bool:
    """Context-aware check: is the character at line[pos] a hidden control?

    Presence-alone detection (pre-v2.6.1) flagged ordinary Persian ZWNJ,
    emoji sequences (👨‍👩‍👧, ❤️) and Arabic text using RLM/LRM. Those
    characters stay suspicious OUTSIDE their legitimate context: a ZWJ
    splitting a Latin keyword ("ig‍nore") still fires, as does every
    zero-width space, bidi override, tag-block character and other
    category-Cf format control.
    """

    char = line[pos]
    cp = ord(char)
    prev = line[pos - 1] if pos > 0 else ""
    nxt = line[pos + 1] if pos + 1 < len(line) else ""

    if cp in (0x200C, 0x200D):  # ZWNJ / ZWJ
        legit = (
            (prev and _SHAPING_SCRIPT_RE.match(prev))
            or (nxt and _SHAPING_SCRIPT_RE.match(nxt))
            or (cp == 0x200D and prev and _is_emoji_context(prev))
        )
        return not legit
    if cp in (0x200E, 0x200F, 0x061C):  # LRM / RLM / ALM
        # Direction marks on a line that contains shaping-script characters
        # are line-level layout (e.g. RLM after punctuation in Arabic prose;
        # ALM U+061C is the Arabic-letter mark of the same family), not
        # obfuscation — second and third review rounds. The character itself
        # is excluded from the search: ALM sits INSIDE the Arabic block
        # (U+061C), so counting it would make every ALM "legitimate".
        rest = line[:pos] + line[pos + 1:]
        return not _SHAPING_SCRIPT_RE.search(rest)
    if cp in (0xFE0E, 0xFE0F):  # text/emoji presentation selectors
        # Legit after emoji bases (handled above, cp >= 0x2190) and after
        # digits / symbols for keycap and trademark sequences (1️⃣, ™️).
        # Suspicious only when glued to a Latin/Cyrillic/Greek letter, where
        # an invisible selector has no typographic purpose.
        return bool(prev and _LATIN_CYRILLIC_GREEK_RE.match(prev))
    if 0xFE00 <= cp <= 0xFE0D:  # remaining variation selectors
        return True
    if 0xE0100 <= cp <= 0xE01EF:  # supplementary variation selectors
        return not (prev and _is_cjk(prev))
    return cp in SUSPICIOUS_UNICODE_CODEPOINTS or unicodedata.category(char) == "Cf"


def suspicious_unicode_lines(text: str) -> List[int]:
    """Return 1-based source lines containing suspicious invisible controls."""

    return [
        index
        for index, line in enumerate(text.splitlines(), start=1)
        if any(_suspicious_at(line, pos) for pos in range(len(line)))
    ]


# --- Terminal control characters (v2.5.0, PI-ANSI-INJECT) --------------------

# ESC starts every ANSI escape sequence; the C1 range includes single-byte CSI
# (U+009B), OSC (U+009D) and DCS (U+0090), which VTE-based terminals, kitty and
# WezTerm accept as equivalents of the two-byte ESC forms.
_ANSI_ESCAPE_RE = re.compile("[\x1b\x80-\x9f]")

# Remaining C0 controls (except tab, newline, carriage return) and DEL. Several
# are display-active: VT/FF can clear or paginate the screen, BS erases drawn
# characters, BEL terminates (and can smuggle) OSC payloads.
_ANSI_OTHER_CONTROL_RE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f\x7f]")


def terminal_control_lines(text: str) -> dict:
    """Locate raw terminal-control characters, grouped by attack class.

    Splits on "\\n" only: str.splitlines() also splits on \\r, VT, FF, NEL and
    the FS/GS/RS boundaries, which would silently consume exactly the bytes this
    check exists to find (a carriage-return line-overwrite, for example). One
    trailing "\\r" per line is ignored so ordinary CRLF files stay clean; any
    other carriage return is a mid-line overwrite attempt.
    """

    hits = {"escape": [], "carriage_return": [], "other_control": []}
    for index, line in enumerate(text.split("\n"), start=1):
        body = line[:-1] if line.endswith("\r") else line
        if _ANSI_ESCAPE_RE.search(body):
            hits["escape"].append(index)
        if "\r" in body:
            hits["carriage_return"].append(index)
        if _ANSI_OTHER_CONTROL_RE.search(body):
            hits["other_control"].append(index)
    return hits
