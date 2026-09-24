#!/usr/bin/env python3
"""pi_shield.py — Layered prompt-injection defense for LLM agents.

Five layers:
  1. Normalization   — terminal-control neutralization, unicode, zero-width,
                       homoglyph cleanup
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


# Terminal escape/control characters are neutralized with VISIBLE placeholders
# rather than deletion, so a reviewer (or the model) can still see that an
# artifact was there — the same approach as Trail of Bits' PrintGuard. Only tab
# and newline survive, matching terminal-security guidance (escape every
# control character except tabs and newlines).
ESCAPE_PLACEHOLDER = "␛"  # ␛ — one visible glyph per ESC byte
CR_PLACEHOLDER = "␍"  # ␍ — stray carriage return (line-overwrite vector)
CONTROL_PLACEHOLDER = chr(0xFFFD)  # replacement char — other control bytes

_ANSI_C1_RE = re.compile("[\x80-\x9f]")  # C1 controls incl. single-byte CSI/OSC/DCS
_ANSI_C0_RE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f\x7f]")  # keeps \t \n \r


def _neutralize_format_chars(t):
    """Neutralize invisible Unicode format characters (category Cf).

    The Unicode tag block (U+E0001-U+E007F) is ASCII smuggling: each tag in
    the printable range U+E0020-U+E007E encodes one ASCII character, so a
    payload invisible to the reviewer is still read by the model. Decode that
    range back to ASCII so Layer-3 scoring can see the payload; drop the
    block's non-printable tags (U+E0001, U+E007F). Every remaining Cf format
    character (zero-width, bidi controls, Arabic letter mark, soft hyphen...)
    is stripped — this supersedes the old explicit ZERO_WIDTH + BIDI_CONTROLS
    list with the whole class, matching the scanner's PI-UNICODE-OBFUSCATION
    coverage.
    """
    out = []
    for ch in t:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            out.append(chr(cp - 0xE0000))
        elif unicodedata.category(ch) != "Cf":
            out.append(ch)
    return "".join(out)


def normalize(text):
    """Layer 1 (scoring view): force text into a canonical, inert state.

    This is an aggressive SCORING aid: NFKC and homoglyph folding make
    look-alike evasions visible to the patterns. It is not meant for the
    model-bound output — folding rewrites ordinary Cyrillic/Greek text. Use
    sanitize_output() for the text that is actually passed on.
    """
    t = text.replace("\x1b", ESCAPE_PLACEHOLDER)  # ESC can start any ANSI sequence
    t = _ANSI_C1_RE.sub(CONTROL_PLACEHOLDER, t)
    t = t.replace("\r\n", "\n")  # judge CR only after CRLF is normalized
    t = t.replace("\r", CR_PLACEHOLDER)
    t = _ANSI_C0_RE.sub(CONTROL_PLACEHOLDER, t)
    t = unicodedata.normalize("NFKC", t)
    t = _neutralize_format_chars(t)
    return t.translate(HOMOGLYPHS)


# Category-Cf characters that are legitimate typography and survive in
# model-bound output: ZWNJ shapes Persian/Arabic words (می‌خواهم); ZWJ joins
# emoji sequences (👨‍👩‍👧) and Indic conjuncts. Everything else invisible is
# stripped or decoded so no hidden character reaches the model.
_OUTPUT_KEEP_CF = frozenset({"\u200c", "\u200d"})


def sanitize_output(text):
    """Neutralize text for model-bound output while keeping it human-readable.

    Unlike normalize(), nothing here rewrites visible characters: no NFKC, no
    homoglyph folding, so Russian/Greek text and emoji pass through intact.
    What never passes through:
      * terminal control bytes — replaced with visible placeholders
      * the Unicode tag block — printable tags are DECODED back to visible
        ASCII (nothing invisible may reach the model), non-printable dropped
      * every other invisible format character (zero-width space, bidi
        controls, word joiner, soft hyphen, ...) except ZWNJ/ZWJ above
    """
    t = text.replace("\x1b", ESCAPE_PLACEHOLDER)
    t = _ANSI_C1_RE.sub(CONTROL_PLACEHOLDER, t)
    t = t.replace("\r\n", "\n")
    t = t.replace("\r", CR_PLACEHOLDER)
    t = _ANSI_C0_RE.sub(CONTROL_PLACEHOLDER, t)
    out = []
    for ch in t:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            out.append(chr(cp - 0xE0000))  # smuggled ASCII brought into the open
        elif ch in _OUTPUT_KEEP_CF or unicodedata.category(ch) != "Cf":
            out.append(ch)
    return "".join(out)


# ---------------------------------------------------------------------------
# Layer 2 — Safe delimiting (with closing-tag escape neutralization)
# ---------------------------------------------------------------------------

_DELIM_TAG_RE = re.compile(r"</?\s*" + DELIM + r"\s*>", re.IGNORECASE)


def _fold_probe(text):
    """Length-preserving NFKC fold used ONLY for tag detection.

    Forged tags come in look-alike codepoints — fullwidth ＜／ｕｓｅｒ＿ｄａｔａ＞
    (U+FF1C/U+FF0F/fullwidth letters/U+FF1E), mathematical angle brackets
    ⟨ ⟩, CJK brackets 〈 〉 — that a literal "</user_data>" check misses but
    NFKC folds to the plain ASCII form. Folding char-by-char and keeping a
    fold only when it yields exactly one character keeps probe positions
    aligned with the original, so matches map back byte-for-byte.
    """
    out = []
    for ch in text:
        folded = unicodedata.normalize("NFKC", ch)
        out.append(folded if len(folded) == 1 else ch)
    return "".join(out)


_BRACKET_NEUTRALIZE = {"<": "\u2039", ">": "\u203A"}


def escape_delimiters(text):
    """Neutralize attempts to close/reopen our delimiter from inside the input.

    Attackers send '</user_data><system>...' — or the same tag in fullwidth /
    mathematical / CJK look-alike codepoints — to break out of the container.
    The tag is detected on a length-preserving NFKC fold of the input, then
    the bracket characters are replaced in place in the ORIGINAL text with
    harmless look-alikes, so any codepoint NFKC folds to a single '<'/'>' is
    covered, not two hand-picked ones (third review round).
    Returns (escaped_text, escape_attempts_count).
    """
    probe = _fold_probe(text)
    matches = list(_DELIM_TAG_RE.finditer(probe))
    if not matches:
        return text, 0
    chars = list(text)
    for match in matches:
        for i in range(match.start(), match.end()):
            replacement = _BRACKET_NEUTRALIZE.get(probe[i])
            if replacement is not None:
                chars[i] = replacement
    return "".join(chars), len(matches)


# ---------------------------------------------------------------------------
# Layer 3 — Scored pattern detection
# ---------------------------------------------------------------------------

# --- v2.6.2: incident-driven families ---------------------------------------
# Environment-variable poisoning (Cursor CVE-2026-22708, fixed in 2.3):
# injected text tells the agent to set a shell-startup or hook variable so
# the NEXT benign command executes the payload — "export PAGER=..." turns a
# later "git branch" into code execution, and the allowlist never sees it
# because export/typeset/declare are trusted shell builtins. CORE vars are
# code-exec primitives that essentially never appear in legitimate content;
# HOOK vars (editors, pagers, runtime option strings) occasionally do, so
# they only count when an explicit assignment verb drives them.
ENV_CORE_VARS = (
    "LD_PRELOAD|DYLD_INSERT_LIBRARIES|BASH_ENV|PROMPT_COMMAND|PS4|"
    "GIT_SSH_COMMAND|GIT_EXTERNAL_DIFF|GIT_CONFIG_COUNT|PERL5OPT|"
    "PYTHONSTARTUP|PYTHONINSPECT|LESSOPEN|LESSCLOSE"
)
ENV_HOOK_VARS = (
    "PAGER|GIT_PAGER|GIT_EDITOR|EDITOR|VISUAL|BROWSER|PYTHONWARNINGS|"
    "PERL5LIB|RUBYOPT|RUBYLIB|NODE_OPTIONS|LD_LIBRARY_PATH|"
    "DYLD_PRINT_LIBRARIES|JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS|ENV"
)
# v2.6.3 review fix: the assignment syntax differs per dialect, and the
# pattern must speak each one — export/declare/typeset take NAME=VALUE with
# optional flags and an optional "--" separator, cmd's "set NAME=VALUE" is
# similar, but csh setenv and Windows setx take NAME VALUE separated by a
# space (no "="). v2.6.2 required "=" for all of them, so the documented
# setenv/setx forms scored zero.
# v2.6.4: quoted spellings tolerated on every dialect (setx "PAGER" "C:\x",
# set "PAGER=C:\x") — cmd users quote habitually. Remaining documented
# limits: value-side quoting variations, assignment via `read`, and
# env(1)-style prefixes; the bare-core assignment form covers the rest.
ENV_VERB_RE = (
    r"\b(?:"
    r"(?:export|declare|typeset)(?:\s+-[a-zA-Z]{1,3})?(?:\s+--)?\s+\"?"
    r"(?:" + ENV_CORE_VARS + "|" + ENV_HOOK_VARS + r")\"?\s*="
    r"|set\s+\"?(?:" + ENV_CORE_VARS + "|" + ENV_HOOK_VARS + r")\"?\s*="
    r"|(?:setenv|setx)\s+\"?(?:" + ENV_CORE_VARS + "|" + ENV_HOOK_VARS + r")\"?\s*[ =]\s*\S"
    r")"
)
ENV_CORE_RE = r"\b(?:" + ENV_CORE_VARS + r")\s*="

# Markdown-image destinations (v2.6.2; widened v2.6.3 to the CommonMark
# forms a renderer honours — <angle> destinations, an optional title after
# the URL — matched case-insensitively so HTTPS:// counts too). The
# query-bearing form is the EchoLeak exfiltration channel; the bare
# protocol-relative form carries no data but is still a render callback to
# an attacker-chosen host (GrafanaGhost).
MD_IMG_QUERY = r"!\[[^\]]*\]\(\s*<?(?:https?:)?//[^)\s>]*[?=&]"
MD_IMG_BARE_PROTOREL = (
    r"!\[[^\]]*\]\(\s*<?//[^)\s>?=\'\"]*>?(?:\s+[\'\"][^)\n]*[\'\"])?\s*\)"
)

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
    (r"\bno (restrictions|guidelines|rules)\b|\bjailbreak\b", 35, "jailbreak attempt"),
    (r"\bnew (directive|instruction|rule)s?\s*[:=]", 25, "directive injection"),
    # v2.6.2 — environment-variable poisoning (see ENV_* above). Weights
    # stack like the other families: a bare core assignment warns (35), the
    # verb-driven instruction shape warns higher (45), and both together —
    # "export LD_PRELOAD=..." — cross the block threshold (80). Hook vars
    # with a verb (export EDITOR=vim) warn once; bare hook mentions
    # (NODE_OPTIONS=--max-old-space-size in a pasted log) stay silent.
    (ENV_VERB_RE, 45, "environment-variable poisoning"),
    (ENV_CORE_RE, 35, "environment-variable poisoning"),
    # v2.6.2 — concealment: the payload orders the agent to hide its actions
    # from the user (the silent half of the Gemini calendar-invite attack,
    # January 2026, and of every masquerade payload since). v2.6.4: the
    # three phrasings are ONE family at a single weight — same-surface
    # duplicates must not stack ("Do not tell + Hide from" was 40+35).
    # Independent evidence still stacks by design (see the env family).
    (r"\b(?:do\s+not|don'?t|never)\s+(?:inform|tell|notify|alert|warn)\s+(?:the\s+)?user\b"
     r"|\bwithout\s+(?:telling|informing|notifying|alerting)\s+(?:the\s+)?user\b"
     r"|\b(?:hide|keep|conceal)\b[^\n]{0,30}\bfrom\s+(?:the\s+)?user\b",
     40, "concealment instruction"),
    # v2.6.2 — markdown image with a query-bearing URL, scheme optional:
    # the EchoLeak exfiltration markup, including the protocol-relative
    # "//host" form that bypasses scheme checks (GrafanaGhost, 2026).
    (MD_IMG_QUERY, 45, "markdown exfiltration channel"),
]

# Model-output channels (Layer 5 companion). Compiled case-insensitively —
# v2.6.2 missed an upper-case scheme here while mcp_guard caught it through
# its own flags (review round 5).
MD_IMG_QUERY_RE = re.compile(MD_IMG_QUERY, re.IGNORECASE)
_MD_IMG_BARE_PROTOREL_RE = re.compile(MD_IMG_BARE_PROTOREL, re.IGNORECASE)

# Case-sensitive patterns: the DAN acronym ("Do Anything Now") is all-caps.
# Matching it case-insensitively flagged every input mentioning a person
# named Dan ("Hi, I'm Dan" scored 35 — a false positive).
CASE_SENSITIVE_PATTERNS = [
    (r"\bDAN\b", 35, "jailbreak attempt"),
]


def score_patterns(text):
    """Return (score, [(label, weight), ...]) for a piece of text."""
    hits = []
    score = 0
    fired_labels = set()
    for pattern, weight, label in PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            hits.append((label, weight))
            score += weight
            fired_labels.add(label)
    for pattern, weight, label in CASE_SENSITIVE_PATTERNS:
        # Same finding family as a case-insensitive tuple: fire once, exactly
        # as when DAN was an alternative inside that tuple — never stacked.
        if label in fired_labels:
            continue
        if re.search(pattern, text):
            hits.append((label, weight))
            score += weight
            fired_labels.add(label)
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

    # Layer 1: two views of the same input. `norm` is the aggressive scoring
    # view (NFKC + homoglyph folding expose look-alike evasion to patterns);
    # `out` is the faithful model-bound view (controls neutralized, hidden
    # characters stripped, but visible text untouched — Cyrillic stays
    # Cyrillic, ZWNJ/ZWJ typography and emoji sequences survive).
    norm = normalize(user_text)
    out = sanitize_output(user_text)
    if out != user_text:
        notes.append("input contained terminal-control/hidden unicode characters — neutralized")

    # Layer 3 (raw text scoring, before wrapping)
    score, hits = score_patterns(norm)
    findings.extend(f"{label} (+{weight})" for label, weight in hits)

    # Layer 2: delimiter escape attempt? Detection runs on both views — the
    # scoring view also catches fullwidth-look-alike tags via NFKC; the
    # neutralizing replacement is applied to the model-bound view.
    escaped, escapes_out = escape_delimiters(out)
    _, escapes_norm = escape_delimiters(norm)
    escapes = max(escapes_out, escapes_norm)
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


# Reference-style images — full CommonMark forms (sixth review round):
#   ![alt][id]   (full)      ![id][]   (collapsed)      ![id]   (shortcut)
# with the destination defined later as [id]: <url> (optionally titled).
# Inline images ![]() are excluded by the negative lookahead — they were
# already flagged by the inline patterns.
_MD_IMG_REF_USE_RE = re.compile(r"!\[([^\]]*)\](?:\[([^\]]*)\])?(?!\()")
_MD_LINK_DEF_RE = re.compile(
    r"(?m)^[ \t]{0,3}\[([^\]]+)\]:[ \t]*<?([^>\s]+)>?"
    r"(?:[ \t]+[\"'(][^\"')\n]*[\"')])?[ \t]*$"
)
_FENCE_ANY_RE = re.compile(r"^[ \t]{0,3}(`{3,}|~{3,})(.*)$")


def _strip_fenced_blocks(text):
    """Remove fenced code blocks, CommonMark-correctly (sixth/seventh
    review rounds). A fence opener is a ``` or ~~~ run of 3+; a BACKTICK
    fence's info string may not contain a backtick ("```bad`info" is not
    a fence — the content under it is ordinary markdown and an image
    there is live), while a TILDE fence's info string may contain anything
    (verified against marked 17.0.5). Content lines and the closing fence
    (same character, length >= opener, trailing spaces only) drop out;
    unterminated fences drop everything to the end, matching CommonMark's
    auto-close."""
    out = []
    fence_ch = None
    fence_len = 0
    for line in text.split("\n"):
        if fence_ch is None:
            m = _FENCE_ANY_RE.match(line)
            if m:
                run, info = m.group(1), m.group(2)
                if run[0] == "`" and "`" in info:
                    out.append(line)  # not a fence — info has a backtick
                    continue
                fence_ch, fence_len = run[0], len(run)
                continue  # opener line drops
            out.append(line)
        else:
            if re.match(r"^[ \t]{0,3}" + re.escape(fence_ch) +
                        r"{%d,}[ \t]*$" % fence_len, line):
                fence_ch, fence_len = None, 0
            # content lines (and the closing fence) drop either way
    return "\n".join(out)


def check_output_channels(model_output):
    """Flag exfiltration channels in model OUTPUT before it is rendered.

    check_output() watches for planted canaries; this watches for the
    rendering channels that carry data out on their own:

    * markdown images whose URL query string can smuggle data to a remote
      host — the EchoLeak pattern — including the protocol-relative
      "//host" form that bypasses scheme allowlists (GrafanaGhost);
    * bare protocol-relative images, which carry no query but are still a
      render callback to an attacker-chosen host.

    Coverage (v2.6.3): inline destinations in both plain and <angle> form
    with an optional title, case-insensitive schemes, and reference-style
    images whose definition carries a suspicious URL. Fenced code blocks
    are excluded — markup inside them renders as literal text. A regex
    layer still is not a full CommonMark parser: the enforceable control is
    a load policy in the renderer/network layer; an empty result here means
    "no indicators within this coverage", not "safe output".

    Returns a list of human-readable findings (empty = no indicators).
    """
    findings = []
    # The analysis view normalizes line endings: a CRLF document must reach
    # the same verdict as its LF twin (seventh review round: a stray \r
    # defeated the fence-closing match and swallowed the image after it).
    text = _strip_fenced_blocks(
        model_output.replace("\r\n", "\n").replace("\r", "\n"))
    for match in MD_IMG_QUERY_RE.finditer(text):
        findings.append(
            "markdown image with query-bearing URL (exfiltration channel): "
            + match.group(0)[:80]
        )
    for match in _MD_IMG_BARE_PROTOREL_RE.finditer(text):
        findings.append(
            "protocol-relative markdown image (render callback): "
            + match.group(0)[:80]
        )
    # Reference-style: an image usage whose link definition resolves to a
    # suspicious destination. Full/collapsed/shortcut forms all count.
    # Labels are normalized the CommonMark way — internal whitespace runs
    # collapse to a single space (seventh review round: "two words" vs
    # "two  words" is the same label).
    def _label(s):
        return " ".join(s.split()).lower()

    used = {}
    for alt, ref_id in _MD_IMG_REF_USE_RE.findall(text):
        key = _label(ref_id if ref_id else alt)
        if key:
            used[key] = True
    if used:
        for ref, url in _MD_LINK_DEF_RE.findall(text):
            if _label(ref) not in used:
                continue
            lowered = url.lower()
            if lowered.startswith("//"):
                findings.append(
                    "reference-style markdown image with protocol-relative URL "
                    f"(render callback): ![...][{ref.strip()}] -> {url[:60]}"
                )
            elif re.match(r"https?://", lowered) and re.search(r"[?=&]", url):
                findings.append(
                    "reference-style markdown image with query-bearing URL "
                    f"(exfiltration channel): ![...][{ref.strip()}] -> {url[:60]}"
                )
    return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _main():
    if len(sys.argv) > 1:
        # newline="": carriage returns are attack signals (line overwrite);
        # do not let universal-newline translation erase them before Layer 1.
        with open(sys.argv[1], "r", encoding="utf-8", errors="replace", newline="") as fh:
            text = fh.read()
    else:
        try:
            sys.stdin.reconfigure(newline="")
        except (AttributeError, ValueError):
            pass  # stdin replaced by a non-TextIOWrapper (tests, embeddings)
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
