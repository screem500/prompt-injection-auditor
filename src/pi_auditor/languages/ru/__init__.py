"""Built-in Russian language pack."""

import re

from ..base import LanguagePack
from .normalizer import normalize_russian, suspicious_unicode_lines
from . import rules

_CYRILLIC_RE = re.compile(r"[А-Яа-яЁё]")


def detect_russian(text: str) -> float:
    count = len(_CYRILLIC_RE.findall(text))
    if not count:
        return 0.0
    return min(1.0, count / 8.0)


PACK = LanguagePack(
    code="ru", name="Russian", version="1.0.0",
    normalize=normalize_russian, detect=detect_russian,
    attack_rules=tuple(rules.RUSSIAN_INJECTION_PATTERNS),
    defensive_context_patterns=tuple(rules.RUSSIAN_DEFENSIVE_CONTEXT_PATTERNS),
    capabilities={
        "script": "Cyrillic", "mixed_language": True,
        "suspicious_unicode_lines": suspicious_unicode_lines,
        "hierarchy_patterns": tuple(rules.RUSSIAN_HIERARCHY_PATTERNS),
        "nondisclosure_patterns": tuple(rules.RUSSIAN_NONDISCLOSURE_PATTERNS),
        "role_claim_patterns": tuple(rules.RUSSIAN_ROLE_CLAIM_PATTERNS),
        "output_constraint_patterns": tuple(rules.RUSSIAN_OUTPUT_CONSTRAINT_PATTERNS),
        "untrusted_content_patterns": tuple(rules.RUSSIAN_UNTRUSTED_CONTENT_PATTERNS),
        "refusal_patterns": tuple(rules.RUSSIAN_REFUSAL_PATTERNS),
        "tool_risk_keywords": tuple(rules.RUSSIAN_TOOL_RISK_KEYWORDS),
        "ingest_keywords": tuple(rules.RUSSIAN_INGEST_KEYWORDS),
        "mcp_present_patterns": tuple(rules.RUSSIAN_MCP_PRESENT_PATTERNS),
        "mcp_mutable_patterns": tuple(rules.RUSSIAN_MCP_MUTABLE_PATTERNS),
        "memory_patterns": tuple(rules.RUSSIAN_MEMORY_PATTERNS),
        "memory_guard_patterns": tuple(rules.RUSSIAN_MEMORY_GUARD_PATTERNS),
        "supply_chain_fetch_patterns": tuple(rules.RUSSIAN_SUPPLY_CHAIN_FETCH_PATTERNS),
    },
)

__all__ = ["PACK", "normalize_russian", "suspicious_unicode_lines", "rules"]
