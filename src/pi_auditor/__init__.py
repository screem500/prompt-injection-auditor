"""Prompt Injection Auditor public package API."""

from .scanner import risk_score, scan, verdict
from .shield import ALLOW, BLOCK, WARN, ShieldResult, check_output, shield_input
from .mcp_guard import GuardResult, guard_tool_definition, guard_tool_response
from .languages import LanguagePack, detect_languages, get_language_pack, list_language_packs, resolve_language_packs
from .session import SessionPolicy, SessionResult, SessionRiskState, SessionTurn

__all__ = [
    "ALLOW",
    "BLOCK",
    "WARN",
    "GuardResult",
    "LanguagePack",
    "ShieldResult",
    "SessionPolicy",
    "SessionResult",
    "SessionRiskState",
    "SessionTurn",
    "check_output",
    "detect_languages",
    "get_language_pack",
    "list_language_packs",
    "resolve_language_packs",
    "guard_tool_definition",
    "guard_tool_response",
    "risk_score",
    "scan",
    "shield_input",
    "verdict",
]

__version__ = "3.0.0a8"
