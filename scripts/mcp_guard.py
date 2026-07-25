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

# Reuse pi_shield's battle-tested layers. Works both when imported as
# scripts.mcp_guard (tests, repo root) and when run directly (CLI).
try:
    from scripts.pi_shield import normalize, score_patterns, scan_encoded
except ImportError:  # direct execution: python scripts/mcp_guard.py
    from pi_shield import normalize, score_patterns, scan_encoded

# Arabic support is optional at import time so older checkouts still run.
try:
    from scripts.normalization import normalize_arabic
    from scripts.language_rules import ARABIC_INJECTION_PATTERNS
except ImportError:
    try:
        from normalization import normalize_arabic
        from language_rules import ARABIC_INJECTION_PATTERNS
    except ImportError:
        normalize_arabic = None
        ARABIC_INJECTION_PATTERNS = None

ALLOW, WARN, BLOCK = "ALLOW", "WARN", "BLOCK"

_FLAGS = re.IGNORECASE | re.MULTILINE | re.DOTALL

# ---------------------------------------------------------------------------
# MCP-specific patterns
# (regex, weight, label). Weights follow pi_shield's 0-100 scale; >=60 blocks.
# ---------------------------------------------------------------------------

MCP_PATTERNS = [
    # Model special tokens — legitimate inside chat templates, NEVER inside
    # tool DATA. Any occurrence means someone is trying to forge the transcript.
    (r"<\|(?:im_start|im_end|endoftext|system|assistant|user)\|?>", 60, "model special-token injection"),
    (r"<<\s*/?\s*SYS\s*>>|\[\s*/?\s*INST\s*\]", 60, "model special-token injection"),
    (r"</?(?:system|assistant)\s*>", 60, "role-tag injection"),
    (r"^\s*#{1,4}\s*(?:system|instructions?)\s*$", 30, "fake markdown system header"),

    # Fake consent — a tool result cannot know what the user approved. Injected
    # "yes, proceed" lines are the classic human-in-the-loop bypass.
    (r"\b(?:the\s+)?(?:user|human|operator)\s+(?:has\s+)?(?:approved|confirmed|consented|agreed|said\s+yes)\b", 50, "fake user consent"),
    (r"\b(?:approval|confirmation|consent)\s*[:=]\s*(?:yes|true|granted)\b", 50, "fake user consent"),
    (r"\byes\b[^\n]{0,20}\b(?:proceed|go\s+ahead|continue\s+with)\b", 25, "fake user consent"),

    # Pushing the agent toward a dangerous follow-up action.
    (r"\bproceed\b[^\n]{0,40}\b(?:delet|send|transfer|execut|run|drop|wipe|email|message|post|upload)", 25, "dangerous-action endorsement"),

    # Tool-call manipulation — steering the agent to invoke other tools.
    (r"\b(?:call|invoke|execute|use|run)\s+(?:the\s+)?[\w-]{0,30}\s*(?:tool|function)\b", 25, "tool-call manipulation"),
    (r"\b(?:tool_call|function_call)\b|\"name\"\s*:\s*\"(?:send_|delete_|transfer_|exec)", 30, "tool-call manipulation"),

    # Exfiltration channels — markdown images/links whose URL query string can
    # carry stolen data to an attacker host (the EchoLeak pattern).
    (r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?=&]", 60, "markdown exfiltration channel"),
    (r"https?://[^\s)\]]*(?:webhook\.site|requestbin|hookbin|ngrok|canarytokens|burpcollaborator|oastify|interact\.sh|pipedream)", 60, "known exfiltration endpoint"),

    # Hidden instruction channels.
    (r"<!--[^>]*(?:ignore|instruction|system|prompt|secret|password|token|previous)[^>]*-->", 35, "hidden instruction in HTML comment"),

    # Context poisoning — trying to persist attacker text into future turns.
    (r"\b(?:remember|store|save|add)\b[^\n]{0,40}\b(?:to\s+(?:your\s+)?(?:context|memory|system\s+prompt)|for\s+later)\b", 30, "context poisoning"),
]

# Unicode "tag block" characters — invisible text that survives copy/paste and
# some normalizers. Detected on RAW text before normalization strips them.
_UNICODE_TAG_RE = re.compile(r"[\U000E0000-\U000E007F]")

# Tool data is never a command channel, so a single high-severity Arabic
# injection hit inside a tool response is enough to block outright.
_AR_SEVERITY_WEIGHT = {"Critical": 60, "High": 60, "Medium": 25, "Low": 10}


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

def _scan_chunk(text):
    """Run the full guard pipeline on one string. Returns (score, findings)."""
    findings = []
    score = 0

    # 0. Invisible unicode tag block — detect on RAW text (normalizers strip it)
    if _UNICODE_TAG_RE.search(text):
        findings.append("invisible unicode tag characters (+60)")
        score += 60

    # 1. Normalize: NFKC, zero-width/bidi/homoglyph cleanup, then Arabic
    #    diacritics/tatweel/letter-variant cleanup (v2.1 rules, if present).
    norm = normalize(text)
    if normalize_arabic is not None:
        norm = normalize_arabic(norm)

    # 2. pi_shield base patterns (instruction override, persona hijack, ...)
    base_score, hits = score_patterns(norm)
    score += base_score
    findings.extend(f"{label} (+{weight})" for label, weight in hits)

    # 3. MCP-specific patterns
    for pattern, weight, label in MCP_PATTERNS:
        if re.search(pattern, norm, _FLAGS):
            findings.append(f"{label} (+{weight})")
            score += weight

    # 4. Arabic injection rules
    if ARABIC_INJECTION_PATTERNS:
        for rule in ARABIC_INJECTION_PATTERNS:
            patterns = rule.get("patterns", [])
            if any(re.search(p, norm) for p in patterns):
                weight = _AR_SEVERITY_WEIGHT.get(rule.get("severity"), 20)
                findings.append(f"{rule.get('id', 'PI-AR')}: {rule.get('title', 'arabic injection')} (+{weight})")
                score += weight

    # 5. Encoded payloads — decode base64/hex blobs and scan their contents
    enc_score, enc_findings = scan_encoded(norm)
    score += enc_score
    findings.extend(enc_findings)

    return min(score, 100), findings


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


def guard_tool_response(text, tool_name="", warn_at=30, block_at=60):
    """Pass an MCP tool response through the guard.

    Accepts plain text or a JSON document (string). When JSON is detected,
    every string value is scanned independently and findings carry their JSON
    path. The decision is driven by the highest-scoring chunk:
      ALLOW  — pass through (use `sanitized`, the wrapped form)
      WARN   — pass through but log/flag for monitoring
      BLOCK  — reject before it reaches the model context
    """
    findings, notes = [], []

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

    max_score = 0
    for path, chunk in chunks:
        if not chunk.strip():
            continue
        chunk_score, chunk_findings = _scan_chunk(chunk)
        max_score = max(max_score, chunk_score)
        prefix = f"{path}: " if path else ""
        findings.extend(f"{prefix}{f}" for f in chunk_findings)

    decision = BLOCK if max_score >= block_at else (WARN if max_score >= warn_at else ALLOW)
    return GuardResult(decision=decision, score=max_score, findings=findings,
                       notes=notes, sanitized=wrap_tool_response(text, tool_name))


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
