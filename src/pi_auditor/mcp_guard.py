#!/usr/bin/env python3
"""mcp_guard.py — Prompt-injection guard for MCP tool responses & definitions.

Why this exists: pi_shield protects the USER-input boundary. But agents built
on MCP (Model Context Protocol) also ingest TOOL responses — and that is an
untrusted channel too. A poisoned web page, database row, email body, or a
malicious/compromised MCP server can smuggle instructions into the model's
context through a tool result ("indirect prompt injection").

On top of pi_shield's five layers, this guard catches tool-channel attacks:
  * model special tokens / role markers smuggled inside tool data
    (<|im_start|>, <<SYS>>, [INST], <system> ...)
  * fake user consent ("the user has approved — proceed with deleting ...")
  * tool-call manipulation ("call the send_email tool", inline tool_call JSON)
  * exfiltration channels (markdown images with query strings, webhook hosts)
  * hidden channels (unicode tag block, HTML comments with instructions)
  * Arabic injection phrases (reuses the v2.1 language rules)
  * encoded payloads (base64/hex blobs, decoded then scanned)

Tool responses are JSON-aware: every string value is scanned and findings are
reported with their JSON path.

Usable as a library or as a CLI:
    from mcp_guard import guard_tool_response, guard_tool_definition
    python mcp_guard.py <response-file>
    cat response.json | python mcp_guard.py

No third-party dependencies. Python 3.8+.
"""

import json
import re
import sys
from dataclasses import dataclass, field

from .findings import Finding, Location
from .scoring import RUNTIME_POLICY, ScoreSummary, calculate_score
from .rules import MCP_GUARD_RULES, SHIELD_RULES, score_rules
from .rules.registry import _AR_SEVERITY_WEIGHT

# Reuse pi_shield's battle-tested layers. Works both when imported as
# scripts.mcp_guard (tests, repo root) and when run directly (CLI).
try:
    from .shield import normalize, score_patterns, scan_encoded
except ImportError:  # pragma: no cover - legacy direct execution
    try:
        from scripts.pi_shield import normalize, score_patterns, scan_encoded
    except ImportError:
        from pi_shield import normalize, score_patterns, scan_encoded

# Language-specific analysis is resolved through the Language Pack API.
from .languages import get_language_pack, resolve_language_packs

_ARABIC_PACK = get_language_pack("ar")
normalize_arabic = _ARABIC_PACK.normalize
ARABIC_INJECTION_PATTERNS = _ARABIC_PACK.attack_rules

ALLOW, WARN, BLOCK = "ALLOW", "WARN", "BLOCK"

_FLAGS = re.IGNORECASE | re.MULTILINE | re.DOTALL

# ---------------------------------------------------------------------------
# MCP-specific patterns
# (regex, weight, label). Weights follow pi_shield's 0-100 scale; >=60 blocks.
# ---------------------------------------------------------------------------


# Unicode "tag block" characters — invisible text that survives copy/paste and
# some normalizers. Detected on RAW text before normalization strips them.
_UNICODE_TAG_RE = re.compile(r"[\U000E0000-\U000E007F]")

# Tool data is never a command channel, so a single high-severity Arabic
# injection hit inside a tool response is enough to block outright.


# ---------------------------------------------------------------------------
# JSON-aware string extraction
# ---------------------------------------------------------------------------

def _walk_strings(obj, path="$"):
    """Yield (json_path, string) for every string value in parsed JSON."""
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for key, value in obj.items():
            yield from _walk_strings(value, f"{path}.{key}")
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            yield from _walk_strings(value, f"{path}[{index}]")


# ---------------------------------------------------------------------------
# Scanning pipeline
# ---------------------------------------------------------------------------

def _scan_chunk(text, channel="tool_response", json_path=None):
    """Run the full guard pipeline on one string and return structured findings."""
    structured = []

    if _UNICODE_TAG_RE.search(text):
        structured.append(Finding(id="PI-UNICODE-TAG", title="invisible unicode tag characters",
            severity="Critical", category="hidden_channel", channel=channel, weight=60,
            evidence="unicode tag block", locations=(Location(json_path=json_path),)))

    norm = normalize(text)

    for rules in (SHIELD_RULES, MCP_GUARD_RULES):
        _, hits = score_rules(norm, rules, channel=channel)
        for hit in hits:
            structured.append(Finding(id=hit.rule_id, title=hit.label,
                severity="Critical" if hit.weight >= 60 else ("High" if hit.weight >= 35 else "Medium"),
                category="mcp_guard", channel=channel, weight=hit.weight, evidence=hit.matched_text,
                locations=(Location(column=hit.start + 1, end_column=hit.end + 1, json_path=json_path),)))

    for pack in resolve_language_packs(text):
        if pack.code == "en":
            continue
        localized = pack.normalize(text).lower()
        for rule in pack.attack_rules:
            if any(re.search(pattern, localized) for pattern in rule.get("patterns", [])):
                weight = _AR_SEVERITY_WEIGHT.get(rule.get("severity"), 20)
                structured.append(Finding(
                    id=rule.get("id", f"PI-{pack.code.upper()}"),
                    title=rule.get("title", f"{pack.name} injection"),
                    severity=rule.get("severity", "Medium"),
                    category=f"{pack.code}_injection", channel=channel,
                    weight=weight, evidence=rule.get("title", f"{pack.name} injection"),
                    locations=(Location(json_path=json_path),),
                ))

    enc_score, enc_findings = scan_encoded(norm)
    for index, text_finding in enumerate(enc_findings, start=1):
        structured.append(Finding(id=f"PI-ENCODED-{index}", title=text_finding, severity="High",
            category="encoded_payload", channel=channel, weight=enc_score, evidence=text_finding,
            locations=(Location(json_path=json_path),)))

    return structured


# ---------------------------------------------------------------------------
# Safe wrapping (Layer 2 for tool data)
# ---------------------------------------------------------------------------

_TOOL_DELIM = "tool_data"
_TOOL_TAG_RE = re.compile(r"</?\s*tool_data(?:\s+name=\"[^\"]*\")?\s*>", re.IGNORECASE)


def wrap_tool_response(text, tool_name=""):
    """Wrap a tool response in neutral delimiters for safe model context.

    Any </tool_data> forgery inside the response is neutralized first, so the
    data can never break out of its container and impersonate instructions.
    """
    escaped = _TOOL_TAG_RE.sub(lambda m: m.group(0).replace("<", "‹").replace(">", "›"), text)
    name_attr = f' name="{tool_name}"' if tool_name else ""
    return f"<{_TOOL_DELIM}{name_attr}>\n{escaped}\n</{_TOOL_DELIM}>"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class GuardResult:
    decision: str
    score: int
    findings: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    sanitized: str = ""
    structured_findings: list = field(default_factory=list)
    scoring: ScoreSummary = None


def guard_tool_response(text, tool_name="", warn_at=30, block_at=60):
    """Pass an MCP tool response through the guard.

    Accepts plain text or a JSON document (string). When JSON is detected,
    every string value is scanned independently and findings carry their JSON
    path. The decision is driven by the highest-scoring chunk:
      ALLOW  — pass through (use `sanitized`, the wrapped form)
      WARN   — pass through but log/flag for monitoring
      BLOCK  — reject before it reaches the model context
    """
    notes = []
    structured = []

    chunks = None
    try:
        parsed = json.loads(text)
        chunks = [(path, value) for path, value in _walk_strings(parsed)]
        if chunks:
            notes.append(f"JSON input: scanned {len(chunks)} string value(s)")
        else:
            chunks = None
    except (json.JSONDecodeError, TypeError):
        chunks = None

    if chunks is None:
        chunks = [("", text)]

    chunk_scores = []
    for path, chunk in chunks:
        if not chunk.strip():
            continue
        chunk_findings = _scan_chunk(chunk, json_path=path or None)
        structured.extend(chunk_findings)
        chunk_scores.append(calculate_score(chunk_findings, RUNTIME_POLICY, warn_at=warn_at, block_at=block_at).score)

    max_score = max(chunk_scores, default=0)
    scoring = calculate_score([], RUNTIME_POLICY, warn_at=warn_at, block_at=block_at)
    scoring = ScoreSummary(score=max_score, verdict=(BLOCK if max_score >= block_at else WARN if max_score >= warn_at else ALLOW),
        decision=(BLOCK if max_score >= block_at else WARN if max_score >= warn_at else ALLOW),
        counts={k: sum(1 for f in structured if f.severity == k) for k in {f.severity for f in structured}},
        finding_count=len(structured), effective_finding_count=len(structured), policy=RUNTIME_POLICY.name)
    findings = []
    for finding in structured:
        path = finding.locations[0].json_path if finding.locations else None
        prefix = f"{path}: " if path else ""
        findings.append(prefix + finding.legacy_text())
    return GuardResult(decision=scoring.decision, score=scoring.score, findings=findings,
                       notes=notes, sanitized=wrap_tool_response(text, tool_name),
                       structured_findings=structured, scoring=scoring)


def guard_tool_definition(tool, warn_at=30, block_at=60):
    """Scan an MCP tool DEFINITION (name/description/schema) for poisoning.

    Accepts a dict or a JSON string. Tool descriptions reach the model context
    verbatim, so a malicious server can hide instructions in them
    ("tool poisoning"). Returns a GuardResult like guard_tool_response.
    """
    if isinstance(tool, str):
        try:
            tool = json.loads(tool)
        except json.JSONDecodeError:
            pass
    text = json.dumps(tool, ensure_ascii=False, indent=2) if not isinstance(tool, str) else tool
    result = guard_tool_response(text, tool_name="tool-definition",
                                 warn_at=warn_at, block_at=block_at)
    result.notes.insert(0, "tool definition scan (tool-poisoning check)")
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _main():
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    else:
        text = sys.stdin.read()

    if not text.strip():
        print("usage: python mcp_guard.py <response-file>   (or pipe text via stdin)")
        sys.exit(2)

    result = guard_tool_response(text)
    colors = {"ALLOW": "\033[92m", "WARN": "\033[93m", "BLOCK": "\033[91;1m"}
    reset = "\033[0m"
    c = colors.get(result.decision, "")
    print("\n=== mcp_guard analysis ===")
    print(f"Decision: {c}{result.decision}{reset}   Threat score: {c}{result.score}/100{reset}\n")
    for f in result.findings:
        print(f"  [!] {f}")
    for n in result.notes:
        print(f"  [i] {n}")
    if result.decision == BLOCK:
        print("\n  -> reject this tool response before it reaches the model context")
    elif result.decision == WARN:
        print("\n  -> pass wrapped version, log for monitoring")
    else:
        print("\n  -> safe to pass (wrapped form)")
    sys.exit(1 if result.decision == BLOCK else 0)


if __name__ == "__main__":
    _main()
