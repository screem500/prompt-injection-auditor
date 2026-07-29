# Mapping to the CrowdStrike Prompt Injection Taxonomy

This file maps the scanner's rules to CrowdStrike's public taxonomy of prompt
injection methods, so a finding from `pi_scan.py` can be read against a
vendor-neutral reference.

## How the two models differ

The taxonomy classifies **attacks** along two independent axes:

- **IM (Injection Method)** — how the malicious instruction reaches the model.
  Three branches on the current poster: direct (attacker-submitted), indirect
  (user-prompt delivery) and indirect (context-data), with the context-data
  branch carrying the agent-era methods (agent-to-agent, agent memory,
  compromised ingestion).
- **PT (Prompting Technique)** — how the attacker phrases or packages the
  instruction once it arrives. Grouped under three colour classes on the
  2026-05-12 poster: Overt Instruction (Semantic Manipulation,
  Morpho-Syntactic Manipulation, In-Context Learning Exploitation), Cognitive
  Control Bypass (Pragmatic Manipulation), and the evasive class (Instruction
  Reformulation, Prompt Boundary Manipulation, Integrative Instruction
  Prompting, Multimodal Prompting Attacks).

This scanner classifies **defensive weaknesses in a prompt or agent
configuration**. A rule does not detect an attack; it detects the absence of a
control that would blunt one. The mapping below therefore reads:

> when this rule fires, these attack methods become easier or possible

A single real attack usually combines one IM with one or more PTs, which is why
several rules map to more than one entry.

## Verification status

IDs marked ✓ were confirmed against CrowdStrike's published material:
the research blog post of 2026-07-07, which detailed five of the eighteen
additions — PT0197 (Cognitive Token Suppression), PT0198 (Special Token
Injection), PT0200 (Algorithmic Payload Decomposition), PT0201
(Trigger-Activated Rule Addition) and IM0018 (Unwitting User Context-Data
Injection) — and the cybersecurity-101 glossary (PT0001, overt instruction).

Note on sources: the printed poster (checked 2026-05-12) carries **no numeric
IDs at all** — they exist only in the blog announcements and in the interactive
explorer. The explorer holds the full ID list but sits behind a registration
gate; the remaining entries below are therefore given by taxonomy **name
only**, and should have their IDs filled in from the explorer before this
table is cited anywhere.

---

## Prompt-level rules

| Rule | Enables (IM) | Enables (PT) | Note |
|------|--------------|--------------|------|
| `PI-SECRET` | — | Secret Information Probing | A leaked key needs no injection technique at all; the prompt already carries it. Outside the taxonomy's frame, which is why it stays Critical here. |
| `PI-TOOLS` | External Context-Data Injection; Internal Context-Data Injection | — | The EchoLeak-class combination: action capability plus untrusted ingestion. The IM axis is where this bites. |
| `PI-LEAKPHRASE` | — | Secret Information Probing; Instructional Text Completion | The prompt volunteers what an attacker would otherwise have to probe for. |
| `PI-INGEST` | External Context-Data Injection; Unwitting User Context-Data Injection (IM0018 ✓); Compromised-Ingestion-Process Injection | — | Ingestion without a data-marking rule is the whole indirect branch. |
| `PI-UNICODE-OBFUSCATION` | — | Instruction Obfuscation → Orthographic Manipulation; Visual Substitution | Homoglyph and zero-width families. |
| `PI-NO-HIERARCHY` | — | Overt Instruction (PT0001 ✓) → Rule Addition (Trigger-Activated Rule Addition, PT0201 ✓) / Rule Nullification / Rule Substitution | With no stated hierarchy, an added rule competes on equal terms. |
| `PI-NO-NONDISCLOSE` | — | Secret Information Probing; Instructional Text Completion | |
| `PI-NO-ROLEGUARD` | — | Cognitive Control Bypass → Authoritative Context Framing; False Authorization Prompting | Authority spoofing. |
| `PI-NO-OUTPUTLIM` | — | Response Steering Prompting → Output Constraint Prompting; Output Seeding | |
| `PI-NO-DELIMIT` | External Context-Data Injection | Prompt Boundary Manipulation → Textual Boundary Mimicry; Special Token Injection (PT0198 ✓) | The clearest one-to-one match in the table. |
| `PI-NO-REFUSAL` | — | Refusal Suppression → Explicit Refusal Negation; Apology Suppression (family sibling: Cognitive Token Suppression, PT0197 ✓) | |

## 2026 agent-runtime rules

| Rule | Enables (IM) | Enables (PT) | Note |
|------|--------------|--------------|------|
| `PI-MCP` | Agent-to-Agent Injection; External Context-Data Injection | — | Tool metadata is a delivery channel, not just a capability grant. |
| `PI-SANDBOX-BYPASS` | — | Instruction Obfuscation; Algorithmic Payload Decomposition (PT0200 ✓) | Denylists fall to exactly the PT evasion families. |
| `PI-MEMORY` | Agent Memory Injection | — | Direct one-to-one match. |
| `PI-SUPPLY-CHAIN` | Compromised-Ingestion-Process Injection | — | The dependency is the ingestion path. |
| `PI-AUTOLOAD-CONFIG` | Internal Context-Data Injection; Attacker-Compromised External Injection | — | A repository-controlled config file is internal context data with configuration authority. |

## Reviewer-level finding

| Finding | Enables (IM) | Enables (PT) |
|---------|--------------|--------------|
| `PI-EMBEDDED-INSTRUCTION` | Prior-LLM-Output Injection; Agent-to-Agent Injection | Integrative Instruction Prompting |

---

## Coverage gaps

Honest accounting of taxonomy entries this scanner does **not** cover.

**Injection methods with no rule**

- **Agent-to-Agent Injection** — referenced in the manual-review step of
  `SKILL.md` (cross-agent trust) but not detected by the scanner. The clearest
  candidate for the next rule.
- **Prior-LLM-Output Injection** — one model's output becoming another's
  trusted input. No rule.
- **Unwitting User Delivery (IM0005 ✓)** — social engineering that turns a
  legitimate user into the delivery vector, via copied text, embedded media, or
  a compromised browser extension. Not a prompt-side weakness, so arguably out
  of scope; worth stating rather than leaving implied.

**Prompting techniques that static analysis cannot reach**

- **Trigger-Activated Rule Addition (PT0201 ✓)** — a dormant instruction that
  stays inert until a trigger phrase or condition appears. It looks harmless
  during review and changes behaviour later. A single-pass static scan of one
  text cannot detect a payload defined by future conditions.
- **Algorithmic Payload Decomposition (PT0200 ✓)** — instructions fragmented
  into individually benign parts that the model reassembles. `pi_shield.py`
  inspects encoded payloads (base64, hex) but does not attempt fragment
  reassembly. See "Honest Limits" in `defense-architecture.md`.
- **Multimodal Prompting Attacks** — payloads carried in images, audio or
  video. Entirely out of scope for a text scanner, by design.

**Deliberately out of scope**

The majority of the catalogued techniques describe what the attacker writes.
This scanner examines the defender's prompt and configuration. Most PT entries
therefore belong in `attack-patterns.md` and `test-payloads.md` rather than as
scanner rules, and chasing a technique count would mistake breadth for
coverage.

---

## Sources

- CrowdStrike research blog, 2026-07-07 — "CrowdStrike Uncovers New Prompt
  Injection Techniques" (PT0197, PT0198, PT0200, PT0201, IM0018):
  https://www.crowdstrike.com/en-us/blog/crowdstrike-uncovers-new-prompt-injection-techniques/
- Taxonomy poster, last update 2026-05-12 (structure and names; prints no IDs):
  https://www.crowdstrike.com/en-us/resources/infographics/taxonomy-of-prompt-injection-methods/
- Prompt injection 101 glossary (PT0001 example, class definitions):
  https://www.crowdstrike.com/en-us/cybersecurity-101/cyberattacks/prompt-injection/
- Interactive explorer (full ID list; registration-gated):
  https://www.crowdstrike.com/explore/interactive-taxonomy/

---

*The taxonomy is CrowdStrike's work and is referenced here for interoperability.
This mapping is maintained independently and may lag their updates.*
