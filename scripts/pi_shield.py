#!/usr/bin/env python3
"""pi_shield.py — Layered prompt-injection defense for LLM agents.

Five layers:
  1. Normalization   — unicode, zero-width, homoglyph cleanup
  2. Safe delimiting — wraps input in tags AND neutralizes closing-tag escapes
  3. Scored detection — weighted pattern analysis (not blind keyword blocking)
  4. Encoded payload inspection — decodes base64/hex blobs and scans contents
  5. Canary check — verifies model output never contains canary tokens

Usable as a library or as a CLI:
    from pi_shield import shield_input, check_output
    python pi_shield.py <input-file>
    echo "ignore all previous instructions" | python pi_shield.py

No third-party dependencies. Python 3.8+.
"""

import base64
import re
import sys
import unicodedata
from dataclasses import dataclass, field

DELIM = "user_data"

# ---------------------------------------------------------------------------
# Layer 1 — Normalization
# ---------------------------------------------------------------------------

ZERO_WIDTH = ["​", "‌", "‍", "⁠", "﻿"]
BIDI_CONTROLS = ["‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩"]

# Common Cyrillic/Greek look-alikes used to evade keyword filters.
HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "у": "y", "і": "i", "ј": "j", "һ": "h", "ԛ": "q", "ԝ": "w",
    "α": "a", "ε": "e", "ο": "o", "ρ": "p", "ν": "v", "τ": "t",
})


def normalize(text):
    """Layer 1: force text into a canonical, inert state."""
    t = unicodedata.normalize("NFKC", text)
    for ch in ZERO_WIDTH + BIDI_CONTROLS:
        t = t.replace(ch, "")
    return t.translate(HOMOGLYPHS)


# ---------------------------------------------------------------------------
# Layer 2 — Safe delimiting (with closing-tag escape neutralization)
# ---------------------------------------------------------------------------

_DELIM_TAG_RE = re.compile(r"</?\s*" + DELIM + r"\s*>", re.IGNORECASE)


def escape_delimiters(text):
    """Neutralize attempts to close/reopen our delimiter from inside the input.

    Attackers send '</user_data><system>...' to break out of the container.
    Replace the angle brackets of any such tag with harmless look-alikes.
    Returns (escaped_text, escape_attempts_count).
    """
    count = len(_DELIM_TAG_RE.findall(text))
    escaped = _DELIM_TAG_RE.sub(lambda m: m.group(0).replace("<", "‹").replace(">", "›"), text)
    return escaped, count


# ---------------------------------------------------------------------------
# Layer 3 — Scored pattern detection
# ---------------------------------------------------------------------------

# (regex, weight, label). Weights accumulate into a 0-100 threat score.
PATTERNS = [
    (r"\bignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|preceding)\b", 60, "instruction override"),
    (r"\bdisregard\b|\boverride\b.{0,20}\b(instructions?|rules?|guidelines?)\b", 35, "instruction override"),
    (r"\byou are now\b|\bact as\b|\bpretend (to be|you are|you're)\b|\broleplay\b", 25, "persona hijack"),
    (r"\b(system|developer|admin)\s*(mode|message|update|override|directive)\b", 30, "fake system message"),
    (r"\b(repeat|print|reveal|show|output|display|leak)\b.{0,50}\b(system prompt|instructions?|config(uration)?)\b", 35, "prompt extraction"),
    (r"\bwhat were you told\b|\byour (initial |original )?(instructions|rules|prompt)\b", 20, "extraction probe"),
    (r"\b(translate|encode|base64|rot13|hex)\b.{0,40}\b(instructions?|prompt|rules)\b", 30, "output laundering"),
    (r"\bi am (the )?(developer|admin|creator|owner|an? openai)\b", 25, "authority spoofing"),
    (r"\bno (restrictions|guidelines|rules)\b|\bjailbreak\b|\bDAN\b", 35, "jailbreak attempt"),
    (r"\bnew (directive|instruction|rule)s?\s*[:=]", 25, "directive injection"),
]


def score_patterns(text):
    """Return (score, [(label, weight), ...]) for a piece of text."""
    hits = []
    score = 0
    for pattern, weight, label in PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            hits.append((label, weight))
            score += weight
    return min(score, 100), hits


# ---------------------------------------------------------------------------
# Layer 4 — Encoded payload inspection
# ---------------------------------------------------------------------------

_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")
_HEX_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")


def _printable_ratio(s):
    if not s:
        return 0.0
    return sum(c.isprintable() or c.isspace() for c in s) / len(s)


def scan_encoded(text):
    """Decode suspicious encoded blobs and scan their CONTENTS.

    Legitimate long tokens (URLs, hashes) decode to garbage or to harmless
    text, so they pass. Only decoded content that itself matches injection
    patterns raises the score — no blind redaction of normal input.
    """
    findings = []
    extra_score = 0
    for blob in _B64_RE.findall(text):
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8", "ignore")
        except Exception:
            continue
        if _printable_ratio(decoded) > 0.85:
            s, hits = score_patterns(decoded)
            if s:
                findings.append(f"base64 blob decodes to injection payload ({', '.join(l for l, _ in hits)})")
                extra_score += max(30, s)
    for blob in _HEX_RE.findall(text):
        try:
            decoded = bytes.fromhex(blob).decode("utf-8", "ignore")
        except Exception:
            continue
        if _printable_ratio(decoded) > 0.85:
            s, hits = score_patterns(decoded)
            if s:
                findings.append(f"hex blob decodes to injection payload ({', '.join(l for l, _ in hits)})")
                extra_score += max(30, s)
    return min(extra_score, 100), findings


# ---------------------------------------------------------------------------
# Shield pipeline
# ---------------------------------------------------------------------------

ALLOW, WARN, BLOCK = "ALLOW", "WARN", "BLOCK"


@dataclass
class ShieldResult:
    decision: str
    score: int
    findings: list = field(default_factory=list)
    sanitized: str = ""
    notes: list = field(default_factory=list)


def shield_input(user_text, warn_at=30, block_at=60):
    """Pass user input through all five layers.

    Returns ShieldResult. `sanitized` is the text safe to embed in the model
    context (normalized, delimiter-escaped, wrapped). The decision:
      ALLOW  — pass through (sanitized)
      WARN   — pass through but log/flag for monitoring
      BLOCK  — reject before it reaches the model
    """
    findings, notes = [], []

    # Layer 1: normalize
    norm = normalize(user_text)
    if norm != user_text:
        notes.append("input contained hidden unicode (zero-width/homoglyph/bidi) — normalized")

    # Layer 3 (raw text scoring, before wrapping)
    score, hits = score_patterns(norm)
    findings.extend(f"{label} (+{weight})" for label, weight in hits)

    # Layer 2: delimiter escape attempt?
    escaped, escapes = escape_delimiters(norm)
    if escapes:
        findings.append(f"delimiter escape attempt: {escapes} closing/opening tag(s) (+40)")
        score += 40

    # Layer 4: encoded payloads
    enc_score, enc_findings = scan_encoded(norm)
    score += enc_score
    findings.extend(enc_findings)

    score = min(score, 100)
    decision = BLOCK if score >= block_at else (WARN if score >= warn_at else ALLOW)
    sanitized = f"<{DELIM}>\n{escaped}\n</{DELIM}>"

    return ShieldResult(decision=decision, score=score, findings=findings,
                        sanitized=sanitized, notes=notes)


# ---------------------------------------------------------------------------
# Layer 5 — Canary check on model output
# ---------------------------------------------------------------------------

def check_output(model_output, canaries):
    """Verify the model's OUTPUT never contains canary tokens or secrets.

    Plant unique canary strings in system prompts / retrieval stores; if one
    appears in output, the prompt (or data) leaked. Returns list of leaked
    canaries (empty = clean).
    """
    return [c for c in canaries if c in model_output]


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
        print("usage: python pi_shield.py <input-file>   (or pipe text via stdin)")
        sys.exit(2)

    result = shield_input(text)
    colors = {"ALLOW": "\033[92m", "WARN": "\033[93m", "BLOCK": "\033[91;1m"}
    reset = "\033[0m"
    c = colors.get(result.decision, "")
    print(f"\n=== pi_shield analysis ===")
    print(f"Decision: {c}{result.decision}{reset}   Threat score: {c}{result.score}/100{reset}\n")
    for f in result.findings:
        print(f"  [!] {f}")
    for n in result.notes:
        print(f"  [i] {n}")
    if result.decision == BLOCK:
        print(f"\n  -> reject this input before it reaches the model")
    elif result.decision == WARN:
        print(f"\n  -> pass sanitized version, log for monitoring")
    else:
        print(f"\n  -> safe to pass (sanitized form)")
    sys.exit(1 if result.decision == BLOCK else 0)


if __name__ == "__main__":
    _main()
