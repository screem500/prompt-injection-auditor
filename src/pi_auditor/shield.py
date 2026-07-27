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

import re
import sys
import unicodedata
from dataclasses import dataclass, field

from .findings import Finding, Location
from .scoring import RUNTIME_POLICY, ScoreSummary, calculate_score
from .rules import SHIELD_RULES, score_rules
from .languages import resolve_language_packs
from .deobfuscation import decode_candidates, printable_ratio

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
    # Preserve native Russian/Cyrillic text. A small number of Cyrillic
    # characters inside otherwise-Latin text is treated as homoglyph evasion.
    cyrillic = sum("\u0400" <= ch <= "\u04ff" for ch in t)
    latin = sum("A" <= ch <= "Z" or "a" <= ch <= "z" for ch in t)
    if cyrillic >= 4 and cyrillic >= latin:
        return t
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


def score_patterns(text):
    """Return (score, [(label, weight), ...]) for a piece of text."""
    score, rule_hits = score_rules(text, SHIELD_RULES, channel="user_input")
    return score, [(hit.label, hit.weight) for hit in rule_hits]


# ---------------------------------------------------------------------------
# Layer 4 — Encoded payload inspection
# ---------------------------------------------------------------------------

def _scan_decoded_content(decoded):
    """Score decoded text with English and installed language packs."""
    score, hits = score_patterns(decoded)
    labels = [label for label, _ in hits]
    for pack in resolve_language_packs(decoded):
        if pack.code == "en":
            continue
        localized = pack.normalize(decoded).lower()
        skip = tuple(re.compile(pattern) for pattern in pack.defensive_context_patterns)
        for rule in pack.attack_rules:
            for pattern in rule.get("patterns", ()):
                match = re.search(pattern, localized)
                if not match:
                    continue
                window = localized[max(0, match.start()-140):min(len(localized), match.end()+60)]
                if any(rx.search(window) for rx in skip):
                    continue
                weight = {"Critical": 60, "High": 60, "Medium": 25, "Low": 10}.get(rule.get("severity"), 20)
                score = min(100, score + weight)
                labels.append(rule.get("title", f"{pack.name} injection"))
                break
    return score, labels


def scan_encoded(text, max_depth=3, max_output_size=100_000, max_candidates=64):
    """Decode bounded obfuscation layers and scan decoded contents.

    Supports base64, base32, base85, hex, URL percent encoding, HTML
    entities, Python-style Unicode escapes, ROT13, reversal, and nested
    combinations. Encodings are findings only when their decoded contents
    match an injection rule.
    """
    findings = []
    scores = []
    for candidate in decode_candidates(text, max_depth=max_depth,
                                       max_output_size=max_output_size,
                                       max_candidates=max_candidates):
        score, labels = _scan_decoded_content(candidate.value)
        if score:
            findings.append(
                f"{candidate.transform} decodes to injection payload "
                f"({', '.join(dict.fromkeys(labels))})"
            )
            scores.append(max(30, score))
    return min(sum(scores), 100), findings


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
    structured_findings: list = field(default_factory=list)
    scoring: ScoreSummary = None


def shield_input(user_text, warn_at=30, block_at=60):
    """Pass user input through all five layers.

    Returns ShieldResult. `sanitized` is the text safe to embed in the model
    context (normalized, delimiter-escaped, wrapped). The decision:
      ALLOW  — pass through (sanitized)
      WARN   — pass through but log/flag for monitoring
      BLOCK  — reject before it reaches the model
    """
    notes = []
    structured = []

    # Layer 1: normalize
    norm = normalize(user_text)
    if norm != user_text:
        notes.append("input contained hidden unicode (zero-width/homoglyph/bidi) — normalized")

    # Layer 3 (raw text scoring, before wrapping)
    _, rule_hits = score_rules(norm, SHIELD_RULES, channel="user_input")
    for hit in rule_hits:
        structured.append(Finding(
            id=hit.rule_id, title=hit.label, severity="High" if hit.weight >= 60 else "Medium",
            category="prompt_injection", channel="user_input", weight=hit.weight,
            evidence=hit.matched_text, locations=(Location(column=hit.start + 1, end_column=hit.end + 1),),
        ))

    # Language-pack signatures (Arabic, Russian, and future packs).
    for pack in resolve_language_packs(user_text):
        if pack.code == "en":
            continue
        localized = pack.normalize(user_text).lower()
        skip = tuple(re.compile(pattern) for pattern in pack.defensive_context_patterns)
        severity_weight = {"Critical": 60, "High": 60, "Medium": 25, "Low": 10}
        for rule in pack.attack_rules:
            for pattern in rule.get("patterns", ()):
                match = re.search(pattern, localized)
                if not match:
                    continue
                start = max(0, match.start() - 140)
                end = min(len(localized), match.end() + 60)
                if any(rx.search(localized[start:end]) for rx in skip):
                    continue
                weight = severity_weight.get(rule.get("severity"), 20)
                structured.append(Finding(
                    id=rule.get("id", f"PI-{pack.code.upper()}"),
                    title=rule.get("title", f"{pack.name} injection"),
                    severity=rule.get("severity", "Medium"),
                    category=f"{pack.code}_injection", channel="user_input",
                    weight=weight, evidence=match.group(0),
                    locations=(Location(column=match.start() + 1, end_column=match.end() + 1),),
                ))
                break

    # Layer 2: delimiter escape attempt?
    escaped, escapes = escape_delimiters(norm)
    if escapes:
        structured.append(Finding(
            id="PI-DELIMITER-ESCAPE",
            title=f"delimiter escape attempt: {escapes} closing/opening tag(s)",
            severity="High", category="delimiter_escape", channel="user_input", weight=40,
            evidence=f"{escapes} delimiter tag(s)",
        ))

    # Layer 4: encoded payloads
    enc_score, enc_findings = scan_encoded(norm)
    for index, text in enumerate(enc_findings, start=1):
        structured.append(Finding(
            id=f"PI-ENCODED-{index}", title=text, severity="High",
            category="encoded_payload", channel="user_input", weight=enc_score, evidence=text,
        ))

    scoring = calculate_score(structured, RUNTIME_POLICY, warn_at=warn_at, block_at=block_at)
    decision = scoring.decision
    sanitized = f"<{DELIM}>\n{escaped}\n</{DELIM}>"
    findings = [finding.legacy_text() for finding in structured]

    return ShieldResult(decision=decision, score=scoring.score, findings=findings,
                        sanitized=sanitized, notes=notes, structured_findings=structured,
                        scoring=scoring)


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
