# Rule Inventory — pi_scan

Complete index of the scanner's rule IDs: 15 rules, each mapped to its
severity behavior and its defense-checklist item. When a rule ID changes,
update this table in the same commit — an undocumented rule is a broken promise.

## Prompt-level rules (v1.x)

| ID | Severity | What it detects | Checklist |
|----|----------|-----------------|-----------|
| PI-SECRET | Critical | Hardcoded credentials (API keys, tokens, private keys) | #6 |
| PI-TOOLS | Critical | Action tools combined with untrusted-content ingestion (EchoLeak-class) | #9, #10, #11 |
| PI-LEAKPHRASE | High | Prompt text explicitly offers to reveal instructions | #2, #4 |
| PI-INGEST | Medium | Agent ingests untrusted external content (web, email, files) | #5, #14 |
| PI-UNICODE-OBFUSCATION | Medium | Invisible unicode (zero-width, bidi, tag block) in the prompt itself | #13 |
| PI-NO-HIERARCHY | Medium | No stated instruction hierarchy (system > user) | #1 |
| PI-NO-NONDISCLOSE | Medium | No non-disclosure rule for instructions | #2 |
| PI-NO-ROLEGUARD | Medium | Identity/persona claims change behavior | #3 |
| PI-NO-OUTPUTLIM | Medium | No output constraints | #4 |
| PI-NO-DELIMIT | Medium | No delimiting of untrusted content | #5 |
| PI-NO-REFUSAL | Low | No explicit refusal/escalation path | #7 |

## 2026 agent-runtime rules (v2.2, English + Arabic)

| ID | Severity tiers | What it detects | Checklist |
|----|----------------|-----------------|-----------|
| PI-MCP | Medium / High / Critical | MCP surface; agent can add/register tool servers; + execution path or unsafe stdio | #24 |
| PI-SANDBOX-BYPASS | High | String-based command gates with no obfuscation defense; sandbox trust keyed off agent-chosen paths | #25 |
| PI-MEMORY | Medium / High | Persistent memory with no integrity/provenance rule; worse under untrusted ingestion | #26 |
| PI-SUPPLY-CHAIN | Medium / High | Agent installs packages with no name pinning; model picks the names ("slopsquatting") | #27 |

*Note: PI-SUPPLY-CHAIN and PI-SANDBOX-BYPASS are gated on a declared execution capability (`has_exec`). Without an exec surface there is no supply-chain or sandbox risk by design — a prompt that merely discusses installing packages is not flagged.*

## Reviewer-level finding (skill workflow, not the scanner)

| ID | Severity | What it means | Checklist |
|----|----------|---------------|-----------|
| PI-EMBEDDED-INSTRUCTION | Critical | The audited target contains instructions aimed at the auditor itself — reported, never obeyed (see SKILL.md "Handling Target Content") | #23 |
