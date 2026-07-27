"""Russian/Cyrillic normalization helpers."""

import re
import unicodedata

_ZERO_WIDTH_RE = re.compile("[\u00ad\u034f\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
_SPACED_CYRILLIC_RE = re.compile(r"(?<![А-Яа-яЁё])(?:[А-Яа-яЁё][ \t\u00a0]+){2,}[А-Яа-яЁё](?![А-Яа-яЁё])")


def _join_spaced(match):
    return re.sub(r"[ \t\u00a0]+", "", match.group(0))


def normalize_russian(text: str) -> str:
    """Canonicalize Russian text while preserving line count."""
    value = unicodedata.normalize("NFKC", text)
    value = _ZERO_WIDTH_RE.sub("", value)
    value = value.translate(str.maketrans({"Ё": "Е", "ё": "е"}))
    return _SPACED_CYRILLIC_RE.sub(_join_spaced, value)


def suspicious_unicode_lines(text: str):
    return [
        index for index, line in enumerate(text.splitlines(), start=1)
        if _ZERO_WIDTH_RE.search(line)
    ]
