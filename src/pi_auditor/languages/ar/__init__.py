"""Built-in Arabic language pack."""

import re

from ..base import LanguagePack
from .normalizer import normalize_arabic, suspicious_unicode_lines
from . import rules

_ARABIC_RE = re.compile(r"[\u0600-\u06FF]")


def detect_arabic(text: str) -> float:
    count = len(_ARABIC_RE.findall(text))
    if not count:
        return 0.0
    # A few Arabic codepoints are enough to activate the pack in code-switched
    # payloads; confidence rises with observed script content.
    return min(1.0, count / 8.0)


PACK = LanguagePack(
    code="ar",
    name="Arabic",
    version="1.0.0",
    normalize=normalize_arabic,
    detect=detect_arabic,
    attack_rules=tuple(rules.ARABIC_INJECTION_PATTERNS),
    defensive_context_patterns=tuple(rules.ARABIC_DEFENSIVE_CONTEXT_PATTERNS),
    capabilities={
        "script": "Arabic",
        "mixed_language": True,
        "suspicious_unicode_lines": suspicious_unicode_lines,
        "hierarchy_patterns": tuple(rules.ARABIC_HIERARCHY_PATTERNS),
        "nondisclosure_patterns": tuple(rules.ARABIC_NONDISCLOSURE_PATTERNS),
        "role_claim_patterns": tuple(rules.ARABIC_ROLE_CLAIM_PATTERNS),
        "output_constraint_patterns": tuple(rules.ARABIC_OUTPUT_CONSTRAINT_PATTERNS),
        "untrusted_content_patterns": tuple(rules.ARABIC_UNTRUSTED_CONTENT_PATTERNS),
        "refusal_patterns": tuple(rules.ARABIC_REFUSAL_PATTERNS),
        "tool_risk_keywords": tuple(rules.ARABIC_TOOL_RISK_KEYWORDS),
        "ingest_keywords": tuple(rules.ARABIC_INGEST_KEYWORDS),
        "mcp_present_patterns": tuple(rules.ARABIC_MCP_PRESENT_PATTERNS),
        "mcp_mutable_patterns": tuple(rules.ARABIC_MCP_MUTABLE_PATTERNS),
        "memory_patterns": tuple(rules.ARABIC_MEMORY_PATTERNS),
        "memory_guard_patterns": tuple(rules.ARABIC_MEMORY_GUARD_PATTERNS),
        "supply_chain_fetch_patterns": tuple(rules.ARABIC_SUPPLY_CHAIN_FETCH_PATTERNS),
    },
)

__all__ = ["PACK", "normalize_arabic", "suspicious_unicode_lines", "rules"]
