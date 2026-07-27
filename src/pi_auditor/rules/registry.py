"""Central compiled rule registry built from installed language packs.

Raw linguistic assets live under ``pi_auditor.languages``. This module only
compiles those assets into channel-aware PatternRule objects and retains legacy
constant aliases for backward compatibility.
"""

import re
from typing import Dict, Tuple

from ..languages import get_language_pack
from .models import PatternRule

_EN = get_language_pack("en")

def _one(name):
    values = _EN.get(name)
    return values[0] if values else ""

SECRET_PATTERNS = _EN.get("secret_patterns")
HIERARCHY_PATTERNS = _EN.get("hierarchy_patterns")
NONDISCLOSURE_PATTERNS = _EN.get("nondisclosure_patterns")
ROLE_CLAIM_PATTERNS = _EN.get("role_claim_patterns")
OUTPUT_CONSTRAINT_PATTERNS = _EN.get("output_constraint_patterns")
UNTRUSTED_CONTENT_PATTERNS = _EN.get("untrusted_content_patterns")
REFUSAL_PATTERNS = _EN.get("refusal_patterns")
LEAK_PRONE_PATTERNS = _EN.get("leak_prone_patterns")
TOOL_RISK_KEYWORDS = _EN.get("tool_risk_keywords")
INGEST_KEYWORDS = _EN.get("ingest_keywords")
EXEC_TOOL_PATTERN = _one("exec_tool_patterns")
MCP_PRESENT_PATTERN = _one("mcp_present_patterns")
MCP_MUTABLE_PATTERN = _one("mcp_mutable_patterns")
MCP_UNSAFE_PATTERN = _one("mcp_unsafe_patterns")
SANDBOX_GATE_PATTERN = _one("sandbox_gate_patterns")
SANDBOX_BYPASS_AWARE_PATTERN = _one("sandbox_bypass_aware_patterns")
SANDBOX_WORKDIR_PATTERN = _one("sandbox_workdir_patterns")
MEMORY_PATTERN = _one("memory_patterns")
MEMORY_GUARD_PATTERN = _one("memory_guard_patterns")
SUPPLY_CHAIN_FETCH_PATTERN = _one("supply_chain_fetch_patterns")
SUPPLY_CHAIN_MODEL_NAMED_PATTERN = _one("supply_chain_model_named_patterns")
SHIELD_PATTERN_TUPLES = _EN.get("shield_pattern_tuples")
MCP_PATTERN_TUPLES = _EN.get("mcp_pattern_tuples")
_AR_SEVERITY_WEIGHT = _EN.get("severity_weights")

SHIELD_RULES: Tuple[PatternRule, ...] = tuple(
    PatternRule(id=f"SHIELD-{i:03d}", pattern=p, label=l, weight=w,
        category="prompt_injection",
        channels=frozenset({"user_input", "tool_response", "tool_definition"}),
        flags=re.IGNORECASE)
    for i, (p, w, l) in enumerate(SHIELD_PATTERN_TUPLES, 1)
)
MCP_GUARD_RULES: Tuple[PatternRule, ...] = tuple(
    PatternRule(id=f"MCP-{i:03d}", pattern=p, label=l, weight=w,
        category="mcp_guard", channels=frozenset({"tool_response", "tool_definition"}),
        flags=re.IGNORECASE | re.MULTILINE | re.DOTALL)
    for i, (p, w, l) in enumerate(MCP_PATTERN_TUPLES, 1)
)
_RULESETS: Dict[str, Tuple[PatternRule, ...]] = {"shield": SHIELD_RULES, "mcp": MCP_GUARD_RULES}

def get_rules(name: str) -> Tuple[PatternRule, ...]:
    try:
        return _RULESETS[name]
    except KeyError as error:
        raise KeyError(f"unknown rule set: {name}") from error
