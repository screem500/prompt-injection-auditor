# Defense Architecture — pi_shield

Layered prompt-injection defense. Read this when implementing input protection for an agent, or when explaining why no single filter is enough.

## Contents

- The Five Layers
- Usage
- Honest Limits (read before trusting any filter)
- Bypass Techniques Defeated by Design

## The Five Layers

### Layer 1 — Normalization

Attackers evade keyword filters with invisible characters (zero-width spaces, bidi overrides) and look-alike letters (Cyrillic/Greek homoglyphs). Normalization forces input into a canonical state: NFKC unicode normalization, zero-width/bidi stripping, homoglyph mapping to Latin. **Every later layer operates on normalized text only.**

### Layer 2 — Safe Delimiting

Wrapping input in `<user_data>` tags helps the model treat it as data — but naive implementations forget that the attacker controls the content and can send `</user_data><system>...` to break out. pi_shield **neutralizes any delimiter tag appearing inside the input** before wrapping, and counts the attempt as an attack signal (+40).

### Layer 3 — Scored Detection

Blind keyword blocking fails: too easy to evade, too many false positives. Instead, ~10 weighted attack patterns (override, persona hijack, extraction, authority spoofing, laundering, fake system messages) accumulate into a 0–100 threat score with a three-state decision:

- **ALLOW** (<30): pass sanitized
- **WARN** (30–59): pass sanitized, log for monitoring
- **BLOCK** (≥60): reject before reaching the model

### Layer 4 — Encoded Payload Inspection

Naive shields redact anything that looks like base64 — breaking legitimate URLs and hashes. pi_shield instead **decodes** base64/hex blobs and scans the *contents*: a tracking ID decodes to harmless bytes and passes; a blob decoding to "ignore all previous instructions" scores as an attack.

### Layer 5 — Canary Output Check

Plant unique canary tokens in the system prompt and retrieval stores. After every model response, `check_output()` verifies none leaked. A canary in the output = the prompt or data escaped — alert immediately.

## Usage

Library:

```python
from pi_shield import shield_input, check_output

result = shield_input(user_message)
if result.decision == "BLOCK":
    reject(result.findings)
else:
    context = system_prompt + result.sanitized   # wrapped <user_data> form
    # ... call model ...
    leaks = check_output(model_reply, canaries=["CANARY-X9Z2"])
```

CLI:

```bash
python pi_shield.py suspicious_input.txt
echo "ignore all previous instructions" | python pi_shield.py
```

Run the proof suite: `python test_shield.py` (11 attack/benign cases).

## Honest Limits

Prompt-level filtering is **one layer of defense, never the whole wall**:

- Determined attackers with multi-turn access (crescendo attacks), novel encodings, or semantic paraphrases can still evade pattern-based layers. Filters raise cost; they do not guarantee safety.
- Real resilience is **architectural**: least-privilege tools, human confirmation for consequential actions, egress filtering, sandboxed execution, session isolation (see defense-checklist.md items 9–22).
- Treat WARN/BLOCK events as telemetry: repeated probing from one session/user is itself an attack signal worth acting on.
- Re-test after every change: run `test_shield.py` and the live payloads from test-payloads.md.

## Bypass Techniques Defeated by Design

| Technique | Naive shield | pi_shield |
|---|---|---|
| `</user_data>` closing-tag escape | breaks out completely | tags neutralized + scored as attack |
| Zero-width characters in keywords | invisible to filters | stripped in Layer 1 |
| Cyrillic/Greek homoglyphs ("ignоre") | passes as different word | mapped to Latin in Layer 1 |
| Base64-encoded commands | either missed, or over-blocked as "encoded" | decoded and contents scanned |
| Long legitimate tokens (URLs, hashes) | false-positive redaction | decoded content is harmless → ALLOW |
| Benign text containing "system" | keyword false positive | weighted patterns need attack structure |
