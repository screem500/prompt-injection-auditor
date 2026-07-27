"""Bounded decoding/deobfuscation utilities for prompt-injection analysis.

All transforms are deterministic and resource-limited. Decoded candidates are
returned for inspection; callers decide whether their contents are malicious.
"""
from __future__ import annotations

import base64
import codecs
import html
import re
from dataclasses import dataclass
from typing import Callable, Iterable, List, Set
from urllib.parse import unquote


@dataclass(frozen=True)
class DecodedCandidate:
    transform: str
    value: str
    depth: int
    source: str = ""


_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")
_B32_RE = re.compile(r"\b[A-Z2-7]{16,}={0,6}\b", re.IGNORECASE)
_HEX_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")
_B85_RE = re.compile(r"(?<!\S)[A-Za-z0-9!#$%&()*+\-;<=>?@^_`{|}~.]{20,}(?!\S)")
_PERCENT_RE = re.compile(r"(?:.*%[0-9a-fA-F]{2}){3,}", re.DOTALL)
_HTML_RE = re.compile(r"&(?:#\d+|#x[0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]+);")
_UNICODE_ESCAPE_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}|\\x[0-9a-fA-F]{2}){2,}")
_ROT13_HINT_RE = re.compile(r"\b(?:vtaber|cerivbhf|vafgehpgvbaf|flfgrz|cebzcg|erirny|vtaber)\b", re.I)


def printable_ratio(value: str) -> float:
    if not value:
        return 0.0
    return sum(ch.isprintable() or ch.isspace() for ch in value) / len(value)


def _safe_text(data: bytes, max_output_size: int) -> str | None:
    if len(data) > max_output_size:
        return None
    try:
        value = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(value) > max_output_size or printable_ratio(value) < 0.85:
        return None
    return value


def _decode_unicode_escapes(blob: str, max_output_size: int) -> str | None:
    try:
        value = codecs.decode(blob, "unicode_escape")
    except Exception:
        return None
    return value if len(value) <= max_output_size and printable_ratio(value) >= 0.85 else None


def _extract_once(text: str, max_output_size: int) -> Iterable[DecodedCandidate]:
    for blob in _B64_RE.findall(text):
        try:
            value = _safe_text(base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True), max_output_size)
        except Exception:
            value = None
        if value is not None:
            yield DecodedCandidate("base64", value, 1, blob)

    for blob in _B32_RE.findall(text):
        try:
            value = _safe_text(base64.b32decode(blob.upper() + "=" * (-len(blob) % 8), casefold=True), max_output_size)
        except Exception:
            value = None
        if value is not None:
            yield DecodedCandidate("base32", value, 1, blob)

    for blob in _HEX_RE.findall(text):
        try:
            value = _safe_text(bytes.fromhex(blob), max_output_size)
        except Exception:
            value = None
        if value is not None:
            yield DecodedCandidate("hex", value, 1, blob)

    for blob in _B85_RE.findall(text):
        try:
            value = _safe_text(base64.b85decode(blob), max_output_size)
        except Exception:
            value = None
        if value is not None:
            yield DecodedCandidate("base85", value, 1, blob)

    if _PERCENT_RE.search(text):
        value = unquote(text)
        if value != text and len(value) <= max_output_size:
            yield DecodedCandidate("url-percent", value, 1, text)

    if _HTML_RE.search(text):
        value = html.unescape(text)
        if value != text and len(value) <= max_output_size:
            yield DecodedCandidate("html-entity", value, 1, text)

    for blob in _UNICODE_ESCAPE_RE.findall(text):
        value = _decode_unicode_escapes(blob, max_output_size)
        if value is not None and value != blob:
            yield DecodedCandidate("unicode-escape", value, 1, blob)

    # ROT13 is self-inverse and produces printable text for almost anything;
    # require attack-language hints to avoid broad false positives.
    if _ROT13_HINT_RE.search(text):
        value = codecs.decode(text, "rot_13")
        if value != text and len(value) <= max_output_size:
            yield DecodedCandidate("rot13", value, 1, text)

    # Reversal is similarly broad. Only expose it for sufficiently long text;
    # downstream attack-pattern matching remains the actual detection gate.
    if 16 <= len(text) <= max_output_size:
        value = text[::-1]
        if value != text:
            yield DecodedCandidate("reversed", value, 1, text)


def decode_candidates(text: str, *, max_depth: int = 3,
                      max_output_size: int = 100_000,
                      max_candidates: int = 64) -> List[DecodedCandidate]:
    """Return unique decoded forms using bounded recursive expansion."""
    if max_depth < 1 or max_output_size < 1 or max_candidates < 1:
        return []
    root = text[:max_output_size]
    queue = [(root, 0, "raw")]
    seen: Set[str] = {root}
    output: List[DecodedCandidate] = []
    while queue and len(output) < max_candidates:
        current, depth, chain = queue.pop(0)
        if depth >= max_depth:
            continue
        for candidate in _extract_once(current, max_output_size):
            value = candidate.value
            if not value or value in seen or len(value) > max_output_size:
                continue
            seen.add(value)
            transform = candidate.transform if chain == "raw" else f"{chain}>{candidate.transform}"
            item = DecodedCandidate(transform, value, depth + 1, candidate.source)
            output.append(item)
            queue.append((value, depth + 1, transform))
            if len(output) >= max_candidates:
                break
    return output
