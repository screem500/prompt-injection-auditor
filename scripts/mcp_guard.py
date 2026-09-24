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
  * exfiltration channels (markdown images with query strings — including
    the protocol-relative "//host" form — webhook hosts)
  * environment-variable poisoning (shell startup/hook variables a tool
    tells the agent to export so the next benign command runs the payload)
  * memory-write instructions ("remember that the user prefers X" — the
    MINJA / Sleeper memory-poisoning shape, English and Arabic)
  * concealment / masquerade instructions ("do not inform the user",
    "respond with 'everything is fine'")
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

import base64
import json
import re
import sys
import unicodedata
from dataclasses import dataclass, field

# Reuse pi_shield's battle-tested layers. Works both when imported as
# scripts.mcp_guard (tests, repo root) and when run directly (CLI).
try:
    from scripts.pi_shield import (
        normalize, sanitize_output, score_patterns, _fold_probe,
        _B64_RE, _HEX_RE, _printable_ratio,
        ENV_VERB_RE, ENV_CORE_RE, MD_IMG_QUERY, MD_IMG_BARE_PROTOREL,
    )
except ImportError:  # direct execution: python scripts/mcp_guard.py
    from pi_shield import (
        normalize, sanitize_output, score_patterns, _fold_probe,
        _B64_RE, _HEX_RE, _printable_ratio,
        ENV_VERB_RE, ENV_CORE_RE, MD_IMG_QUERY, MD_IMG_BARE_PROTOREL,
    )

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
    # <s>/</s> are real BOS/EOS tokens (Llama, Mistral). Kept at warn weight:
    # NLP corpus data can carry them legitimately, but inside tool data they
    # usually mean transcript forgery.
    (r"</?s>", 30, "BOS/EOS token smuggling"),
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
    # carry stolen data to an attacker host (the EchoLeak pattern). The scheme
    # is optional since v2.6.2: the protocol-relative "//host" form bypasses
    # scheme allowlists (GrafanaGhost). A bare protocol-relative image carries
    # no query but is still a render callback, so it warns.
    (MD_IMG_QUERY, 60, "markdown exfiltration channel"),
    (MD_IMG_BARE_PROTOREL, 30, "protocol-relative markdown image (render callback)"),
    (r"https?://[^\s)\]]*(?:webhook\.site|requestbin|hookbin|ngrok|canarytokens|burpcollaborator|oastify|interact\.sh|pipedream)", 60, "known exfiltration endpoint"),

    # Environment-variable poisoning (v2.6.2; Cursor CVE-2026-22708, fixed in
    # 2.3): tool data tells the agent to set a shell startup/hook variable so
    # the NEXT benign command executes the payload — export/typeset/declare
    # are trusted builtins, so the allowlist never sees the assignment. The
    # verb-driven form is the instruction shape (+45); a bare core-variable
    # assignment in the data warns (+40) and the two stack. Patterns are
    # shared with pi_shield so both layers see the same variable set.
    (ENV_VERB_RE, 45, "environment-variable poisoning"),
    (ENV_CORE_RE, 40, "environment-variable poisoning"),

    # Memory-write instructions (v2.6.2; MINJA and the Sleeper memory-
    # poisoning campaigns): tool data orders the agent to persist attacker
    # text into long-term memory, where it replays with system-prompt
    # authority in every future session. "remember that …" alone is weak
    # evidence (documentation says it too), so it warns only in combination;
    # the explicit forms ("commit to memory", "from now on always") warn on
    # their own. Arabic forms are matched on the normalized view.
    (r"\bremember\s+(?:that|this|these)\b", 25, "memory-write instruction"),
    (r"\bfrom\s+now\s+on\b[^\n]{0,40}\b(?:always|remember|treat|use|do|never|consider)\b", 30, "memory-write instruction"),
    (r"\b(?:in|for)\s+future\s+(?:sessions?|conversations?|interactions?|reference)\b", 30, "memory-write instruction"),
    (r"\bcommit\s+(?:this|it|that|these)\s+to\s+(?:your\s+)?memory\b", 40, "memory-write instruction"),
    (r"\bupdate\s+your\s+(?:memory|records|knowledge|notes|preferences|beliefs)\b", 35, "memory-write instruction"),
    (r"\u062a\u0630\u0643\u0631\s+(?:\u0627\u0646|\u0647\u0630\u0627|\u0647\u0630\u0647)\b", 25, "memory-write instruction"),
    (r"\u0645\u0646\s+\u0627\u0644\u0627\u0646\s+\u0641\u0635\u0627\u0639\u062f\u0627", 30, "memory-write instruction"),
    (r"(?:\u0627\u062d\u0641\u0638|\u062e\u0632\u0646|\u0633\u062c\u0644)\b[^\n]{0,40}(?:\u0630\u0627\u0643\u0631\u062a|\u0630\u0643\u0631\u064a|\u0645\u0644\u0627\u062d\u0638\u0627\u062a)", 40, "memory-write instruction"),

    # Concealment / masquerade (v2.6.2; Gemini calendar-invite injection,
    # January 2026): the payload's second half orders the agent to hide the
    # action and hand the user a canned harmless answer ("respond with 'it's
    # a free time slot'"). The do-not-inform forms warn at +50; the canned-
    # answer shape is weaker (API documentation quotes responses) so it only
    # counts in combination.
    (r"\b(?:do\s+not|don'?t|never)\s+(?:inform|tell|notify|alert|warn)\s+(?:the\s+)?user\b", 50, "concealment instruction"),
    (r"\bwithout\s+(?:telling|informing|notifying|alerting)\s+(?:the\s+)?user\b", 50, "concealment instruction"),
    (r"\b(?:hide|keep|conceal)\b[^\n]{0,30}\bfrom\s+(?:the\s+)?user\b", 45, "concealment instruction"),
    (r"\btell\s+the\s+user\s+(?:that\s+)?(?:everything|all|it)\s+is\s+(?:fine|ok(?:ay)?|normal|safe)\b", 45, "masquerade instruction"),
    (r"\b(?:respond|reply|answer)\s+with\s+['\"]", 25, "masquerade instruction"),
    (r"(?:\u0644\u0627\s+\u062a\u062e\u0628\u0631|\u0644\u0627\s+\u062a\u0628\u0644\u063a|\u0644\u0627\s+\u062a\u0639\u0644\u0645|\u0644\u0627\s+\u062a\u062d\u0630\u0631)\s+\u0627\u0644\u0645\u0633\u062a\u062e\u062f\u0645", 50, "concealment instruction"),
    (r"(?:\u062f\u0648\u0646|\u0628\u062f\u0648\u0646)\s+(?:\u0627\u062e\u0628\u0627\u0631|\u0627\u0628\u0644\u0627\u063a|\u0627\u0639\u0644\u0627\u0645)\s+\u0627\u0644\u0645\u0633\u062a\u062e\u062f\u0645", 50, "concealment instruction"),

    # Hidden instruction channels.
    (r"<!--[^>]*(?:ignore|instruction|system|prompt|secret|password|token|previous)[^>]*-->", 35, "hidden instruction in HTML comment"),

    # Context poisoning — trying to persist attacker text into future turns.
    (r"\b(?:remember|store|save|add)\b[^\n]{0,40}\b(?:to\s+(?:your\s+)?(?:context|memory|system\s+prompt)|for\s+later)\b", 30, "context poisoning"),
]

# Unicode "tag block" characters — invisible text that survives copy/paste and
# some normalizers. Detected on RAW text before normalization strips them.
_UNICODE_TAG_RE = re.compile(r"[\U000E0000-\U000E007F]")

# OSC 52 (clipboard write): ESC ] 52 ; or the C1 single-char form \x9d 52.
_OSC52_RE = re.compile("(?:\x1b\\]|\x9d)52[;:]")

# Terminal sequences that are dangerous in their own right, each +60 (BLOCK),
# matched on RAW text. SGR color/rendition stays weightless on purpose
# (captured build logs carry it) — but SGR 8 (conceal) is NOT a color: it is
# the exact "invisible to the reviewer, readable to the model" primitive
# PI-ANSI-INJECT describes, so it blocks (third review round).
_ANSI_DANGEROUS = [
    (re.compile("\x1b\\[(?:[0-9]*;)*8(?:;[0-9]*)*m"),
     "terminal conceal attribute (SGR 8)"),
    (re.compile("(?:\x1b\\]|\x9d)8[;:]"),
     "terminal hyperlink sequence (OSC 8)"),
    (re.compile("\x1b\\[[0-9]{2,}b"),
     "terminal repeat-character flood (REP)"),
    (re.compile("(?:\x1bP|\x90)"),
     "device control string (DCS)"),
]

# Tool data is never a command channel, so a single high-severity Arabic
# injection hit inside a tool response is enough to block outright.
_AR_SEVERITY_WEIGHT = {"Critical": 60, "High": 60, "Medium": 25, "Low": 10}


# ---------------------------------------------------------------------------
# JSON-aware string extraction
# ---------------------------------------------------------------------------

def _safe_path_key(key):
    """Render a JSON key for embedding in a finding PATH — display text
    that may be printed to a terminal. v2.6.4 escaped only the $key
    preview and left the raw key inside the VALUE's path (a key carrying
    OSC 52 leaked a raw ESC into CLI stdout, seventh review round);
    v2.6.5 still let the C1 range (U+0080-009F, the single-character OSC
    forms) and invisible format characters (ZWSP, ZWJ, bidi marks, the
    tag block) through (eighth review round). The rule is now categorical:
    every Unicode character whose class starts with C (control, format,
    surrogate, private-use, unassigned) renders as a visible escape;
    everything else passes through readable."""
    out = []
    for ch in key:
        if unicodedata.category(ch).startswith("C"):
            code = ord(ch)
            if code <= 0xFF:
                out.append(f"\\x{code:02x}")
            elif code <= 0xFFFF:
                out.append(f"\\u{code:04x}")
            else:
                out.append(f"\\U{code:08x}")
        else:
            out.append(ch)
    return "".join(out)


def _walk_strings(obj, path="$"):
    """Yield (json_path, string) for every string in parsed JSON.

    Keys included since v2.6.3: a key reaches the model's context exactly
    like a value when the document is re-serialized, so a payload parked in
    a property NAME ({"Ignore all previous instructions": "x"}) is scanned
    too. Key entries carry a $key[...] path marker so a finding tells the
    reviewer where the payload sits. Every key embedding — preview or
    value path — is escaped for display safety.
    """
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(key, str):
                yield f"{path}.$key[{_safe_path_key(key)[:24]}]", key
                yield from _walk_strings(value, f"{path}.{_safe_path_key(key)}")
            else:
                yield from _walk_strings(value, f"{path}.{key}")
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            yield from _walk_strings(value, f"{path}[{index}]")


# ---------------------------------------------------------------------------
# Scanning pipeline
# ---------------------------------------------------------------------------

def _raw_signal_findings(text):
    """The raw-text signal layer: invisible tag block, OSC 52 clipboard
    writes, and the dangerous terminal sequences. These are the only
    checks that must run on UN-normalized bytes — normalizers strip the
    very characters being detected. Shared by the direct chunk path and
    the decoded-blob path (seventh review round: a base64-wrapped OSC 8
    hyperlink decoded to a folded view where the escape no longer existed
    and scored 0). Returns (score, [findings])."""
    findings = []
    score = 0
    if _UNICODE_TAG_RE.search(text):
        findings.append("invisible unicode tag characters (+60)")
        score += 60
    if _OSC52_RE.search(text):
        findings.append("terminal clipboard-write sequence (OSC 52) (+30)")
        score += 30
    for pattern, label in _ANSI_DANGEROUS:
        if pattern.search(text):
            findings.append(f"{label} (+60)")
            score += 60
    return score, findings


def _scan_chunk(text):
    """Run the full guard pipeline on one string. Returns (score, findings)."""
    findings = []
    score = 0

    # 0-0c. Raw-text signal layer (see _raw_signal_findings).
    raw_score, raw_findings = _raw_signal_findings(text)
    score += raw_score
    findings.extend(raw_findings)

    # 1. Normalize: NFKC, zero-width/bidi/homoglyph cleanup, then Arabic
    #    diacritics/tatweel/letter-variant cleanup (v2.1 rules, if present).
    norm = normalize(text)
    if normalize_arabic is not None:
        norm = normalize_arabic(norm)

    # 2-4. Base + MCP + Arabic patterns on the normalized view.
    surf_score, surf_findings = _score_surface(norm)
    score += surf_score
    findings.extend(surf_findings)

    # 5. Encoded payloads — decode base64/hex blobs, then run the SAME
    #    surface on the decoded content, exactly one decode level deep.
    #    v2.6.3 review fix: v2.6.2 rescanned decoded text with the English
    #    base patterns only, so a base64-wrapped <system> tag or an Arabic
    #    override sailed through at 0 while its direct form blocked at 60.
    #    v2.6.4 review fix: the decoded text also crosses the SAME
    #    normalization as direct input (NFKC fold + Arabic normalization) —
    #    previously a diacritized, fullwidth or zero-width-wrapped payload
    #    decoded to raw bytes the patterns were never meant to see.
    enc_score = 0
    for codec, decoded in _decoded_blobs(norm):
        # Raw-signal layer on the decoded BYTES (before normalization
        # strips the escapes being detected), then the full normalized
        # surface — the decoded path now crosses everything direct input
        # crosses.
        sub_raw, sub_raw_findings = _raw_signal_findings(decoded)
        folded = normalize(decoded)
        if normalize_arabic is not None:
            folded = normalize_arabic(folded)
        sub_score, sub_findings = _score_surface(folded)
        sub_score += sub_raw
        sub_findings = sub_raw_findings + sub_findings
        if sub_score:
            labels = ", ".join(f.rsplit(" (+", 1)[0] for f in sub_findings)
            findings.append(
                f"{codec} blob decodes to injection payload ({labels}) "
                f"(+{max(30, sub_score)})"
            )
            enc_score += max(30, sub_score)
    score += min(enc_score, 100)

    return min(score, 100), findings


def _score_surface(norm):
    """Run every pattern layer on an already-normalized string.

    Order: pi_shield base patterns, then the MCP-specific patterns with
    family dedup (a finding family counts once, at its highest weight — a
    stricter MCP weight is applied as the escalation difference, recorded so
    a third pattern of the same family cannot escalate twice), then the
    Arabic injection rules. Shared by the direct path and the decoded-blob
    path so both cross the same checks (review round 5).

    Returns (score, [finding strings]).
    """
    findings = []
    score = 0

    base_score, hits = score_patterns(norm)
    score += base_score
    findings.extend(f"{label} (+{weight})" for label, weight in hits)
    base_by_label = {}
    for label, weight in hits:
        base_by_label[label] = max(base_by_label.get(label, 0), weight)

    for pattern, weight, label in MCP_PATTERNS:
        if re.search(pattern, norm, _FLAGS):
            prev = base_by_label.get(label)
            if prev is None:
                findings.append(f"{label} (+{weight})")
                score += weight
                base_by_label[label] = weight
            elif weight > prev:
                findings.append(
                    f"{label} (+{weight - prev} tool-channel escalation)"
                )
                score += weight - prev
                base_by_label[label] = weight
            # else: the family already stands at an equal or higher weight.

    if ARABIC_INJECTION_PATTERNS:
        for rule in ARABIC_INJECTION_PATTERNS:
            patterns = rule.get("patterns", [])
            if any(re.search(p, norm) for p in patterns):
                weight = _AR_SEVERITY_WEIGHT.get(rule.get("severity"), 20)
                findings.append(f"{rule.get('id', 'PI-AR')}: {rule.get('title', 'arabic injection')} (+{weight})")
                score += weight

    return min(score, 100), findings


def _decoded_blobs(text):
    """Yield (codec, decoded_string) for base64/hex blobs whose decoded form
    is mostly printable text. One level only — decoded content is scored,
    never re-decoded, so a blob nested in a blob cannot loop the scanner."""
    for blob in _B64_RE.findall(text):
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8", "ignore")
        except Exception:
            continue
        if _printable_ratio(decoded) > 0.85:
            yield "base64", decoded
    for blob in _HEX_RE.findall(text):
        try:
            decoded = bytes.fromhex(blob).decode("utf-8", "ignore")
        except Exception:
            continue
        if _printable_ratio(decoded) > 0.85:
            yield "hex", decoded


# --- JSON resource limits (v2.6.4, sixth review round) ----------------------
# Platform-default recursion limits differ (1000 on a stock interpreter,
# higher in some environments), so "it parses fine here" cannot be the
# policy. Two deterministic guards:
#   * _json_nesting_depth — an iterative (non-recursive) bracket counter;
#     documents deeper than _MAX_JSON_DEPTH are never handed to json.loads.
#   * the parse itself catches RecursionError and ValueError (a 5000-digit
#     integer raises ValueError on Python 3.12+ via the int conversion
#     guard), failing over to the plain-text scan.
_MAX_JSON_DEPTH = 400

_JSON_UNESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")


def _json_nesting_depth(text):
    """Maximum bracket nesting of a JSON-looking string, computed
    iteratively. Returns 0 for non-JSON input; quotes are honored so
    brackets inside strings do not count."""
    if not text or text[0] not in "{[":
        return 0
    depth = max_depth = 0
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "{[":
            depth += 1
            if depth > max_depth:
                max_depth = depth
        elif ch in "}]":
            depth = max(0, depth - 1)
    return max_depth


_JSON_SHORT_ESCAPES = {'"': '"', "\\": "\\", "/": "/",
                       "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


def _json_unescape(text):
    """Decode JSON escape sequences (\\uNNNN plus the short \\n \\t \\\\ …
    set) with a single left-to-right pass — no double-decoding, so
    "\\u005cn" yields backslash+n (two characters) exactly as JSON
    specifies. Used only on the parse-failure fallback, where a payload
    written with escape spellings must still be seen by the patterns
    (seventh review round: \\n-escaped deep payloads scored 0)."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "u" and i + 5 < n:
                try:
                    out.append(chr(int(text[i + 2:i + 6], 16)))
                    i += 6
                    continue
                except ValueError:
                    pass
            if nxt in _JSON_SHORT_ESCAPES:
                out.append(_JSON_SHORT_ESCAPES[nxt])
                i += 2
                continue
            out.append(ch)
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _sanitize_json(obj):
    """Rebuild a parsed JSON value with every string — keys included —
    passed through sanitize_output(), so the sanitized form stays valid,
    parseable JSON. If two keys fold into one after sanitization the later
    key keeps its value under a numeric suffix: a silent merge would change
    the document's meaning without a trace (review round 5)."""
    if isinstance(obj, str):
        return sanitize_output(obj)
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            new_key = sanitize_output(key) if isinstance(key, str) else key
            # json.loads already dedups identical keys, so `in out` means a
            # genuine fold-collision (one of the pair changed shape in
            # sanitization) — suffix the later key rather than overwrite.
            if new_key in out:
                suffix = 2
                while f"{new_key} ({suffix})" in out:
                    suffix += 1
                new_key = f"{new_key} ({suffix})"
            out[new_key] = _sanitize_json(value)
        return out
    if isinstance(obj, list):
        return [_sanitize_json(value) for value in obj]
    return obj


# ---------------------------------------------------------------------------
# Safe wrapping (Layer 2 for tool data)
# ---------------------------------------------------------------------------

_TOOL_DELIM = "tool_data"
_TOOL_TAG_RE = re.compile(
    r"</?\s*tool_data(?:\s+name=\"[^\"]*\")?\s*>", re.IGNORECASE)
_BRACKET_NEUTRALIZE = {"<": "\u2039", ">": "\u203A"}

# v2.6.3 review fix: tool_name lands inside the wrapper's name="..."
# attribute, so an untrusted name carrying a quote or a closing tag broke
# out of the attribute and injected markup into the "sanitized" output
# (e.g. tool_name='x</tool_data><system>...' survived with ALLOW/0). The
# name is cosmetic metadata, never authority: reduce it to the MCP tool
# name charset before it is allowed anywhere near the wrapper.
_UNSAFE_TOOL_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_tool_name(name):
    return _UNSAFE_TOOL_NAME_RE.sub("_", name)


def wrap_tool_response(text, tool_name=""):
    """Wrap a tool response in neutral delimiters for safe model context.

    Any </tool_data> forgery inside the response is neutralized first, so the
    data can never break out of its container and impersonate instructions.
    The tool_name is reduced to [A-Za-z0-9._-] before it is embedded in the
    wrapper's attribute — it is metadata, and it must not carry markup.
    """
    # Detect on the length-preserving NFKC fold (fullwidth / mathematical /
    # CJK look-alikes), then neutralize the bracket chars in place — same
    # mechanism as pi_shield.escape_delimiters (third review round).
    probe = _fold_probe(text)
    matches = list(_TOOL_TAG_RE.finditer(probe))
    if matches:
        chars = list(text)
        for match in matches:
            for i in range(match.start(), match.end()):
                replacement = _BRACKET_NEUTRALIZE.get(probe[i])
                if replacement is not None:
                    chars[i] = replacement
        escaped = "".join(chars)
    else:
        escaped = text
    name_attr = f' name="{_safe_tool_name(tool_name)}"' if tool_name else ""
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
    parsed = None
    parsed_ok = False
    parse_failed = None
    # JSON permits insignificant whitespace around the document — every
    # shape decision runs on the stripped view, the original bytes are
    # what gets scanned (seventh review round: a single leading space
    # defeated the depth guard and the escape unwrapping).
    json_view = text.lstrip()
    # A JSON document may be an object, an array — or a bare STRING (the
    # root "…" form). v2.6.5 dropped the string root and regressed it to
    # ALLOW 0 for escaped payloads (eighth review round); '"' is JSON-
    # shaped again. (Scalar numbers/bools carry no string payload.)
    looks_json = bool(json_view) and json_view[0] in '{["'
    if looks_json:
        try:
            if _json_nesting_depth(json_view) <= _MAX_JSON_DEPTH:
                candidate = json.loads(json_view)
                chunks = [(path, value) for path, value in _walk_strings(candidate)]
                if chunks:
                    parsed = candidate
                    parsed_ok = True
                    notes.append(
                        f"JSON input: scanned {len(chunks)} string field(s) (keys and values)"
                    )
                else:
                    chunks = None
            else:
                # Deterministic depth guard: never hand hostile nesting to
                # json.loads at all (platform recursion limits vary; the
                # fallback below runs every pattern on the raw content).
                parse_failed = "depth"
        except RecursionError:
            parse_failed = "depth"
        except json.JSONDecodeError:
            # Well-formed intent, bad syntax: "not JSON", not "limits" —
            # no note, the plain-text scan below still runs. (Must precede
            # ValueError: JSONDecodeError subclasses it.)
            parse_failed = None
        except (TypeError, ValueError):
            # ValueError: a 5000-digit integer raises on Python 3.12+ via
            # the int conversion guard — a genuine resource limit, unlike
            # a plain syntax error.
            parse_failed = "limits"

    if chunks is None:
        chunks = [("", text)]
        if parse_failed == "depth":
            notes.append(
                f"JSON too deeply nested to parse safely (>{_MAX_JSON_DEPTH}) "
                "— scanned as plain text"
            )
        elif parse_failed == "limits":
            notes.append(
                "JSON exceeds parser limits (depth / number width) "
                "— scanned as plain text"
            )
        if looks_json and "\\" in json_view:
            # A JSON-shaped input that failed parsing may carry its payload
            # as escape spellings (\uNNNN, \n, …); the raw-text scan would
            # see only the escapes. Scan the unescaped variant as a second
            # chunk so the payload is still seen (sixth/seventh rounds).
            chunks.append(("", _json_unescape(json_view)))

    max_score = 0
    for path, chunk in chunks:
        if not chunk.strip():
            continue
        chunk_score, chunk_findings = _scan_chunk(chunk)
        max_score = max(max_score, chunk_score)
        prefix = f"{path}: " if path else ""
        findings.extend(f"{prefix}{f}" for f in chunk_findings)

    # The sanitized form is built from the NEUTRALIZED text, never the raw
    # input. Pre-v2.6.1 it wrapped the raw string, so terminal escapes
    # (OSC 52 clipboard writes) and invisible tag characters passed straight
    # into the "safe" wrapped output. JSON inputs are rebuilt value-by-value
    # so the sanitized form stays parseable.
    if parsed_ok:
        try:
            sanitized_body = json.dumps(_sanitize_json(parsed),
                                        ensure_ascii=False, indent=2)
            # The note must mean a value actually changed: re-serializing
            # clean JSON already differs from the original bytes (indent,
            # spacing), so comparing whole strings fires on every clean
            # document (2nd review). Keys are in chunks, so they are
            # compared too (5th review).
            changed = any(sanitize_output(value) != value
                          for _, value in chunks)
        except RecursionError:
            # Same fail-over as the parse path: never crash, never pass the
            # raw deep document through untouched.
            sanitized_body = sanitize_output(text)
            changed = sanitized_body != text
            notes.append("sanitized form rebuilt as plain text (JSON nesting limit)")
    else:
        sanitized_body = sanitize_output(text)
        changed = sanitized_body != text
    if changed:
        notes.append("string values neutralized (terminal-control/hidden characters)")

    decision = BLOCK if max_score >= block_at else (WARN if max_score >= warn_at else ALLOW)
    return GuardResult(decision=decision, score=max_score, findings=findings,
                       notes=notes,
                       sanitized=wrap_tool_response(sanitized_body, tool_name))


def guard_tool_definition(tool, warn_at=30, block_at=60):
    """Scan an MCP tool DEFINITION (name/description/schema) for poisoning.

    Accepts a dict or a JSON string. Tool descriptions reach the model context
    verbatim, so a malicious server can hide instructions in them
    ("tool poisoning"). Returns a GuardResult like guard_tool_response.
    """
    original = tool
    if isinstance(tool, str):
        # Same resource posture as guard_tool_response: a string that is
        # not parseable JSON (or is hostilely deep) is handed through as
        # text instead of crashing the caller (sixth review round); the
        # shape checks run on the whitespace-stripped view (seventh).
        view = tool.lstrip()
        try:
            if view[:1] in "{[" and _json_nesting_depth(view) <= _MAX_JSON_DEPTH:
                tool = json.loads(view)
        except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
            pass
    if isinstance(tool, str):
        text = tool
    else:
        try:
            text = json.dumps(tool, ensure_ascii=False, indent=2)
        except (RecursionError, ValueError):
            # Re-serializing a hostilely deep structure must not crash the
            # caller either — scan the original input as text (seventh
            # review round: RecursionError at json.dumps on 1100 levels).
            text = original if isinstance(original, str) else str(original)
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
