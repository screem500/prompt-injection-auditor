"""Built-in English language pack."""

import re

from ..base import LanguagePack
from . import rules

_LATIN_RE = re.compile(r"[A-Za-z]")

def normalize_english(text: str) -> str:
    return text

def detect_english(text: str) -> float:
    letters = len(_LATIN_RE.findall(text))
    if not letters:
        return 0.0
    all_letters = sum(ch.isalpha() for ch in text)
    return min(1.0, letters / max(4, all_letters))

PACK = LanguagePack(
    code="en", name="English", version="1.1.0",
    normalize=normalize_english, detect=detect_english,
    attack_rules=tuple({
        "id": f"PI-EN-{index:03d}",
        "severity": "High" if weight >= 35 else "Medium",
        "title": label,
        "patterns": (pattern,),
        "detail": "English prompt-injection signature.",
        "fix": "Treat lower-trust content as data and enforce instruction hierarchy.",
    } for index, (pattern, weight, label) in enumerate(rules.SHIELD_PATTERN_TUPLES, 1)),
    capabilities={
        "script": "Latin", "mixed_language": True,
        "secret_patterns": tuple(rules.SECRET_PATTERNS),
        "hierarchy_patterns": tuple(rules.HIERARCHY_PATTERNS),
        "nondisclosure_patterns": tuple(rules.NONDISCLOSURE_PATTERNS),
        "role_claim_patterns": tuple(rules.ROLE_CLAIM_PATTERNS),
        "output_constraint_patterns": tuple(rules.OUTPUT_CONSTRAINT_PATTERNS),
        "untrusted_content_patterns": tuple(rules.UNTRUSTED_CONTENT_PATTERNS),
        "refusal_patterns": tuple(rules.REFUSAL_PATTERNS),
        "leak_prone_patterns": tuple(rules.LEAK_PRONE_PATTERNS),
        "tool_risk_keywords": tuple(rules.TOOL_RISK_KEYWORDS),
        "ingest_keywords": tuple(rules.INGEST_KEYWORDS),
        "exec_tool_patterns": (rules.EXEC_TOOL_PATTERN,),
        "mcp_present_patterns": (rules.MCP_PRESENT_PATTERN,),
        "mcp_mutable_patterns": (rules.MCP_MUTABLE_PATTERN,),
        "mcp_unsafe_patterns": (rules.MCP_UNSAFE_PATTERN,),
        "sandbox_gate_patterns": (rules.SANDBOX_GATE_PATTERN,),
        "sandbox_bypass_aware_patterns": (rules.SANDBOX_BYPASS_AWARE_PATTERN,),
        "sandbox_workdir_patterns": (rules.SANDBOX_WORKDIR_PATTERN,),
        "memory_patterns": (rules.MEMORY_PATTERN,),
        "memory_guard_patterns": (rules.MEMORY_GUARD_PATTERN,),
        "supply_chain_fetch_patterns": (rules.SUPPLY_CHAIN_FETCH_PATTERN,),
        "supply_chain_model_named_patterns": (rules.SUPPLY_CHAIN_MODEL_NAMED_PATTERN,),
        "shield_pattern_tuples": tuple(rules.SHIELD_PATTERN_TUPLES),
        "mcp_pattern_tuples": tuple(rules.MCP_PATTERN_TUPLES),
        "severity_weights": dict(rules.LANGUAGE_SEVERITY_WEIGHT),
    },
)

__all__ = ["PACK", "normalize_english", "rules"]
