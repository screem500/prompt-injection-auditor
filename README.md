# prompt-injection-auditor

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Agent Skills](https://img.shields.io/badge/Agent%20Skills-agentskills.io-green)](https://agentskills.io)
[![Install](https://img.shields.io/badge/npx-skills%20add-orange)](https://skills.sh)

**An open Agent Skill that turns any AI agent into a prompt-injection security auditor.**
Static scanner + attack catalog + defense checklist + authorized red-team payloads — built against real-world incidents like EchoLeak (CVE-2025-32711).

Works with Claude Code, Cursor, Kimi, and 20+ agents that support the open [Agent Skills](https://agentskills.io) standard.

**Measured:** separation between hardened and vulnerable prompts improved from 8.3 to 43.3 points, with zero false positives on the hardened corpus. See [VALIDATION.md](VALIDATION.md).

**Different target:** payload detectors ask "is this input an attack?"; this asks "does your prompt have the controls to blunt one?" Both use patterns — but a missing instruction hierarchy is missing regardless of how an attacker phrases the attempt.

![live demo](demo-prompt-injection-auditor.gif)

## Why?

Prompt injection remains unsolved: there is no general defense, and every published mitigation is probabilistic. Real incidents keep proving it:

- **EchoLeak (CVE-2025-32711, CVSS 9.3)** — the first zero-click prompt injection in a production AI system: hidden instructions in an email made Microsoft 365 Copilot exfiltrate OneDrive/SharePoint data via a markdown image, no clicks needed.
- **LangGrinch (CVE-2025-68664, CVSS 9.3)** — LangChain Core serialization injection: unescaped `lc` keys let LLM-influenced data be rehydrated as objects, enabling secret extraction. The flaw sits in the *serialization* path, not deserialization. LangChain.js carries the parallel CVE-2025-68665 (CVSS 8.6).
- **Langflow (CVE-2025-3248 / CVE-2026-33017)** — unauthenticated RCE in an agent-building framework; the 2026 flaw was exploited in the wild within 20 hours of the advisory, before any public PoC existed. Note that 1.8.2 was widely reported as fixed but remained exploitable — only 1.9.0+ is verified.

In 2026 the threat moved from framework bugs into the agent runtime itself:

- **MCP tool-server exposure (Flowise CVE-2026-40933, CVSS 9.9; Amazon Q CVE-2026-12957)** — a stdio MCP config is a launcher definition: registering a tool server runs arbitrary commands, and one poisoned workspace file made Amazon Q execute a malicious MCP config and leak AWS credentials.
- **Sandbox escapes (Cursor "DuneSlide" CVE-2026-50548/50549, CVSS 9.8; MS-Agent CVE-2026-2256; Codex CLI CVE-2025-59532)** — regex denylists fall to obfuscation, and sandbox trust keyed off agent-chosen paths falls to prompt injection: Codex CLI treated a *model-generated* working directory as the sandbox's writable root.
- **Repo-borne config execution (Codex CLI CVE-2025-61260, CVSS 9.8; Claude Code CVE-2025-59536, CVSS 8.7; Cursor CVE-2025-54136)** — agents auto-load and execute MCP/tool config files from the current repository before any trust check; one malicious repo runs code on open.
- **Slopsquatting (USENIX Security 2025, Spracklen et al.)** — 19.7% of AI-recommended package names don't exist, and 43% of the fakes repeat on every run; attackers pre-register them and agents install them with no human checkpoint.

Most system prompts ship with no instruction hierarchy, no non-disclosure rule, and no untrusted-content handling. This skill finds those weaknesses before attackers do.

## Install

```bash
npx skills add screem500/prompt-injection-auditor
```

## Usage

With the skill installed, just ask your agent:

```
Audit this system prompt against prompt injection: [paste prompt]
```

```
Review my SKILL.md for security weaknesses before I publish it.
```

The agent follows a 5-step methodology: collect target -> run the static scanner -> manual review against the attack catalog -> authorized live testing (optional) -> severity-rated report with fixes.

Instruction files are audited with the same scanner and catalog as any other target. A dedicated skill-file linter mode is on the roadmap.

### Standalone scanner (no agent needed)

```bash
python scripts/pi_scan.py system_prompt.txt                 # terminal report
python scripts/pi_scan.py system_prompt.txt --md report.md  # markdown report
python scripts/pi_scan.py system_prompt.txt --json out.json # CI/automation
```

Exit code is `1` when Critical/High findings exist — drop it straight into your CI pipeline.

## Demo

Scanning a vulnerable prompt (hardcoded API key + email/code-execution tools + reads inbox):

```
=== Prompt Injection Audit: vulnerable_prompt.txt ===
Risk score: 100/100 [####################]  SEVERELY EXPOSED — do not deploy before remediation

[Critical] PI-SECRET: Secret-like value present: Hardcoded credential-like value (lines 2)
[Critical] PI-TOOLS: Powerful capabilities declared: Code/command execution capability;
           Network/egress capability; Outbound messaging capability (lines 4, 5)
           Why: The agent has action capabilities AND ingests untrusted content
           (web/email/RAG) — the EchoLeak-class combination.
[   High] PI-NO-HIERARCHY: No explicit instruction hierarchy
[   High] PI-NO-NONDISCLOSE: No non-disclosure rule for the prompt itself
...
Summary: Critical=2, High=4, Medium=2, Low=1
```

A hardened prompt (hierarchy + non-disclosure + delimiters) scores **0/100 — HARDENED**.

> **What the score means:** this is a static *hygiene* score — it measures whether the prompt states the right controls, not whether the deployed agent resists injection. A 0/100 prompt can still be attacked; adaptive attacks bypass in-band defenses at will (Nasr et al., arXiv 2510.09023). Treat 0/100 as "no static findings", then verify with live tests (SKILL.md, Step 4) and enforce the consequential-action gates outside the model.

## What's inside

```
prompt-injection-auditor/
├── SKILL.md                        # 5-step audit methodology + ethics guardrails (v2.2.0)
├── scripts/
│   ├── pi_scan.py                  # Zero-dependency static analyzer (18 rule IDs — see references/rule-inventory.md)
│   ├── pi_shield.py                # v2.0: layered input defense (5 layers, scored decisions)
│   ├── mcp_guard.py                # v2.2: MCP tool-response guard (JSON-aware)
│   ├── normalization.py            # v2.1: Arabic normalization (diacritics, tatweel, letters)
│   └── language_rules.py           # v2.1+: Arabic injection, context & runtime rules
├── tests/
│   ├── test_shield.py              # 11-case suite proving the shield against evasion
│   ├── test_mcp_guard.py           # 20-case MCP guard suite (v2.2)
│   ├── test_runtime_rules.py       # 19-case 2026 agent-runtime rule suite (v2.2)
│   ├── test_arabic_rules.py        # Arabic injection detection (v2.1)
│   ├── test_normalization.py       # Arabic normalization unit tests (v2.1)
│   ├── test_english_regression.py  # English regression guard
│   ├── test_confirm_gate.py        # 14-case confirmation-gate suite (v2.6)
│   ├── test_fp_regression.py       # 196-case false-positive regression suite (v2.6.7)
│   ├── test_docs_sync.py           # doc-drift guard: inventory, bilingual twins, SKILL.md refs, test count (v2.6)
│   └── test_cli.py                 # CLI end-to-end tests
├── check_redactions.py            # pre-publish sweep: private paths, emails, live-looking credentials (v2.6.1)
├── RELEASING.md                   # additive-only policy + release gate (English + Arabic, v2.6)
├── .github/workflows/tests.yml    # CI: full suite (Linux + Windows, py3.8–3.12) + benchmark/redaction gate (v2.6)
├── VALIDATION.md                  # precision measurement: method, results, limits
└── references/
    ├── attack-patterns.md          # Direct / indirect / encoding / exfiltration / multi-agent
    ├── attack-patterns-2026.md     # MCP poisoning / sandbox bypass / memory injection / slopsquatting
    ├── rule-inventory.md           # All 18 rule IDs: severity behavior + checklist mapping
    ├── defense-checklist.md        # 30 numbered hardening measures
    ├── defense-architecture.md     # The 5-layer shield design + honest limits
    ├── attack-landscape-2026-08.md # 2026 threat/defense research note (English; .ar.md twin in Arabic)
    └── test-payloads.md            # Escalation-ordered payloads for authorized live tests

```

## Pre-registered study (2026-08)

- `PREREGISTRATION.md` — design frozen before data collection (kept byte-frozen as registered)
- `RESULTS.md` — published outcome: declaration metrics, the disclosed deviation from the pre-registered independent-rater item (§8), and reproduction steps (§12)
- `TESTSET_MANIFEST.md` + `manifest-test.jsonl` — test-set chain of custody
- `VALIDATION.md` — precision measurement: method, results, limits

Run the full test suite with `python -m unittest discover tests`.

### New in v2.6.8 — CI matrix restored on Python 3.8/3.10

The v2.6.7 push was the first CI run over the new test code on older Pythons; four matrix jobs failed while 3.12 stayed green. Two causes, both fixed: a `benchmark.py` f-string form that only Python 3.12 parses (multi-line string concatenation inside f-string braces — never parsed on older interpreters until a test started importing it), and two huge-integer tests that assumed Python 3.11+'s int-digit guard (older versions parse the number fine — the tests now pin the cross-version invariant). Suite verified green on 3.11 and 3.12. 337 tests; benchmark and garak unchanged.

### New in v2.6.7 — ninth-round parity pass

The ninth review closed the eighth round's remaining items and kept scope tight, per its own recommendation (`tests/test_fp_regression.py`, 6 new cases):

- **Negation-vocabulary parity**: the gate-negation check now covers the reported regressions and their tested counterparts — "never ask for user **approval**", "…**human** confirmation", "لا تطلب **من المستخدم** تأكيد…" fire the finding again (v2.6.6 had silently regressed them), with the verb→noun bridge allowing the same function words as the positive side. The positive and negation patterns remain separate code; the tests prove these cases, not equivalence for every phrasing. Accumulated gate matrix: 21 cases, all passing.
- **Test hardening**: the C1/ZWSP CLI runs now assert full success conditions (a crash can't pass on absent bytes), and the "unicode-escaped" fixture contains real `\uNNNN` sequences proven to decode.
- **Log wording**: acceptance wording, "byte-for-byte" scope, and the escaping claim corrected to what the reviews actually found.
- Benchmark unchanged (3.0 / 46.3 / 43.3); garak unchanged (111/135/404) — sixth consecutive stable measurement. 337 tests (196 in the regression suite).

### New in v2.6.6 — eighth-round regression sweep

The eighth review confirmed v2.6.5's specific fixes and matched the published metrics (322 tests green on Windows), then caught two regressions that v2.6.5's own fixes had introduced plus a residual display-safety gap — fixed here with attack-side and benign-side tests, no scope expansion, per its recommendation (`tests/test_fp_regression.py`, 9 new cases):

- **JSON string roots restored**: a document that IS a string (`json.dumps("…")`) parses and scans again — v2.6.5 had dropped it to ALLOW 0; malformed documents no longer wear a "limits" note (syntax failure ≠ resource failure).
- **Gate negation binds to the noun**: "never ask irrelevant questions; **get user confirmation**" keeps its real gate; only a negated ask carrying the confirmation ("never ask for user confirmation" / "لا تطلب تأكيد…") suppresses — EN + AR, all ten historical gate cases re-verified.
- **Display escaping is categorical**: every input character whose Unicode class starts with C (C1 OSC forms, ZWSP, ZWJ, bidi marks) renders as a visible escape inside finding paths — input payloads can no longer smuggle control bytes into diagnostic output.
- **Crash-proof CLI test**: asserts the report exists, forbids tracebacks, and adds C1/ZWSP fixtures.
- Benchmark unchanged (3.0 / 46.3 / 43.3); garak unchanged (111/135/404) — fifth consecutive stable measurement. 331 tests (190 in the regression suite).

### New in v2.6.5 — seventh-round precision pass

The seventh review verified v2.6.4 (304 tests green on Windows) and then corrected one of our own claims: the v2.6.4 "CLI leak not reproduced" paragraph was wrong — the leak reproduces with valid JSON (our test had used invalid JSON and missed the path). Fixed, with the reviewer's exact fixture as a regression test (`tests/test_fp_regression.py`, 18 new cases):

- **Display-safe finding paths**: control characters are escaped at every JSON-key embedding — zero raw OSC sequences reach CLI stdout.
- **JSON robustness completed**: shape checks on the whitespace-stripped view (leading space defeated the depth guard), `guard_tool_definition` re-serialization crash-proofed, full single-pass escape decoding on the fallback (`\n`-deep payloads now seen), and honest notes (plain text no longer labeled "exceeds limits").
- **Span-level gate negation**: "Before sending, never ask…" / "قبل إرسال الرسائل لا تطلب…" no longer count as gates.
- **Markdown parity**: CRLF == LF verdicts, tilde fences accept any info string (marked-parity), CommonMark label whitespace collapsing, and decoded blobs now cross the raw terminal-signal layer (base64/hex OSC 8 blocked).
- Benchmark unchanged (3.0 / 46.3 / 43.3); garak unchanged (111/135/404) — fourth consecutive stable measurement. 322 tests.

### New in v2.6.4 — precision fixes after the archive-level review

The sixth review round examined the shipped v2.6.3 zip itself and confirmed its fixes and measurements, then caught one CI-blocker and six precision issues — all reproduced locally and fixed (`tests/test_fp_regression.py`, 24 new cases):

- **Windows CI restored**: the round-5 CR test used a hardcoded `/tmp` path (279/280 on Windows); tempfile now.
- **Encoded payloads fully equivalent**: decoded blobs fold through the same normalization as direct input — diacritized/fullwidth/zero-wrapped payloads no longer pass as base64 at 0.
- **JSON limits completed**: deterministic depth guard, huge-integer `ValueError` caught, `guard_tool_definition` hardened, `\uNNNN`-escaped payloads still seen on the fallback path.
- **Gate negation prefix-scoped**: a real gate later on the same line survives; `must not ask` / `لا تسأل` count as negations; stable across line wraps.
- **CommonMark-correct fences** (` ```bad\`info` is not a fence) and complete reference-image forms (collapsed/shortcut/titled).
- **Concealment = one family, one weight** on the same surface; independent evidence (env) still stacks by design; quoted env dialects (`setx "PAGER" "C:\path"`).
- Original review item #10 (surface-vs-control inference) is **explicitly deferred to v2.7** — stated, not silently absorbed.
- Benchmark unchanged (3.0 / 46.3 / 43.3); garak unchanged (111/135/404, 37.8%). 304 tests.

### New in v2.6.3 — review-driven hardening of the runtime layers

An external cross-suite review of the tagged v2.6.2 reproduced thirteen findings; twelve were verified locally and fixed with attack-side + benign-side tests (`tests/test_fp_regression.py`, 46 new cases) — the thirteenth (scanner surface-vs-control inference) is explicitly deferred to v2.7 and recorded as such in the CHANGELOG:

- **Tool-name injection** closed: names are reduced to `[A-Za-z0-9._-]` before they touch the wrapper's attribute.
- **JSON keys scanned and sanitized** — a payload in a property *name* previously reached the model at ALLOW 0.
- **Markdown grammar widened** to the CommonMark forms renderers honour (`HTTPS://`, `<angle>` destinations, titles, reference-style images), with fenced code blocks excluded from the render gate.
- **Hostile JSON depth** fails over to a plain-text scan — never a crash, never a silent pass.
- **Decoded base64/hex blobs** now cross the full surface (base + MCP + Arabic), one decode level deep.
- **Negated confirmation requests** ("Do not ask for user confirmation" / "لا تطلب تأكيد المستخدم") no longer count as a confirmation gate.
- Plus: family-dedup escalation fix, setenv/setx/export `--` dialects, the خزن spelling, load-time folding of every Arabic pattern (dead ئ/ؤ/ى literals eliminated), and hardened measurement tooling (raw-byte benchmark reads, fully pinned scanner hashes, non-zero exit on mismatch).
- Documentation corrections from the same review: CVE-2026-22708 dated January 14, 2026 with its Auto-Run + Allowlist condition; Sleeper framed as the study it is; VALIDATION/RESULTS arithmetic cleaned up.
- Benchmark unchanged (3.0 / 46.3 / 43.3); garak unchanged (111/135/404, noticed 37.8%). 280 tests.

### New in v2.6.2 — incident-driven runtime families

Four new detection families in the runtime layers (`pi_shield` / `mcp_guard`), each anchored to a disclosed 2026 attack; the scanner's 18 rule IDs are unchanged (`tests/test_fp_regression.py`, 33 new cases):

- **Environment-variable poisoning** (Cursor CVE-2026-22708): instructions to `export` shell startup/hook variables (PAGER, LD_PRELOAD, PERL5OPT, PYTHONWARNINGS, …) score in both layers — the payload that turns the next benign command into code execution. Bare hook-variable strings in pasted logs stay silent by design.
- **Memory-write instructions** (MINJA / Sleeper memory poisoning): tool data saying "remember that…", "commit to memory", "from now on, always…" (English + Arabic) warns and stacks; the user's own "remember that I prefer…" request to their agent is not a finding.
- **Concealment / masquerade** (Gemini calendar-invite injection, Jan 2026): "do not inform the user", "respond with 'everything is fine'" — the silence half of the payload — warns at +50 and stacks to a block; positive phrasing ("please inform the user") stays silent.
- **Protocol-relative markdown images** (GrafanaGhost): `![](//host/x.png?d=…)` blocks like its https form; bare `//host` images warn as render callbacks; new `check_output_channels()` flags both in model output before rendering.
- **Family dedup across guard layers**: a finding family counts once per chunk at its highest weight, with the tool-channel difference applied as escalation.
- Re-measured on the pinned garak in-the-wild corpus (650 prompts): noticed **35.4% → 37.8%**, mean 24.8 → 26.4 — movement traced payload-by-payload to the new families, recorded in the CHANGELOG. Benchmark unchanged: 3.0 / 46.3 / 43.3. 234 tests.

### New in v2.6.1 — review-driven fixes and permanent gates

A pre-tag review of the v2.6.0 candidate probed the rules with realistic text instead of claimed numbers; every reproduced finding is fixed, and three further review rounds added eleven more (`tests/test_fp_regression.py`, 60 cases):

- **Destructive pairing**: PI-TOOLS / PI-NO-CONFIRM-GATE now require a consequential object — "remove unused imports" no longer reports a destructive capability; "delete records/files" still does.
- **mcp_guard sanitized form** is built from the neutralized text: OSC 52 / terminal escapes and invisible tag characters no longer survive into the wrapped "safe" output; JSON stays parseable.
- **pi_shield output fidelity**: the model-bound text keeps Cyrillic, Persian ZWNJ shaping and emoji sequences intact (new `sanitize_output()`), while scoring stays as aggressive as before.
- **Context-aware unicode rule**: ❤️, 👨‍👩‍👧 and Persian/Arabic joiner typography no longer fire PI-UNICODE-OBFUSCATION; the same characters inside Latin keywords still do.
- **Case-sensitive DAN**: a person named Dan is not a jailbreak (was WARN 35).
- **Round 2**: publish/deploy findings require agent voice (CI-workflow descriptions stay quiet), destructive pairing tolerates commas/apostrophes, RLM/VS context extended to line level and keycap/trademark sequences, fullwidth ＜＞ delimiter forgeries neutralized in both wrappers, mcp_guard notes fire only on real change, and OSC 52 clipboard writes score to WARN.
- **Round 3**: fullwidth tag *names* (＜／ｕｓｅｒ＿ｄａｔａ＞) neutralized via a length-preserving NFKC fold in both wrappers, dangerous terminal sequences (conceal SGR 8, OSC 8, REP floods, DCS) block in mcp_guard while SGR colors stay weightless, agent voice is sentence-scoped with CI/workflow suppression, ALM gets the line-level treatment, and deploy/publish accepts an object ("deploy the app to production") with version-number periods no longer splitting the gating sentence.
- **Permanent gates**: `check_redactions.py` (private paths / emails / live-looking credentials), a CI `gate` job running the benchmark with a true separation gate, and a CHANGELOG test-count drift check. 201 tests.

### New in v2.6 — confirmation-gate rule, CI, and the bilingual documentation policy

- **`PI-NO-CONFIRM-GATE`** (rule 18): consequential actions (send / delete / pay / publish / deploy) declared with no confirmation, staging, or stop rule — High, Critical under untrusted ingestion. Anchored to the OpenClaw inbox-deletion incident (2026-02-23, OWASP GenAI Exploit Round-up Q1 2026) and the out-of-band defense literature. English + Arabic gate detection; checklist #30.
- **Continuous integration**: the full suite now runs on every push and PR across Linux and Windows, Python 3.8–3.12, plus CLI smoke tests (`.github/workflows/tests.yml`).
- **Documentation drift guard**: `tests/test_docs_sync.py` wires `check_rule_docs.py` into the test suite and adds two new checks — every Arabic twin document covers the same rule IDs as its English base, and every file `SKILL.md` names actually exists.
- **Bilingual documentation policy**: English documents gain Arabic twins (`references/<name>.ar.md`), starting with the 2026 landscape research note. Twins may differ in wording, never in coverage — enforced by test.
- **Additive-only release policy**: `RELEASING.md` (English + Arabic) — rule IDs are permanent, existing tests are never deleted, corpus scores move only with a named reason in the CHANGELOG.
- **Research note**: `references/attack-landscape-2026-08.md` (+ Arabic twin) maps the 2026 threat and defense landscape onto this rule set with sources, and carries the backlog the roadmap below draws from.

### New in v2.2 — 2026 agent-runtime rules (scanner)

pi_scan now detects the five weakness families that dominated 2026 incidents, in English **and Arabic** (`references/attack-patterns-2026.md`):

- **PI-MCP** — agent can add/register MCP tool servers (Medium/High/Critical tiers; Flowise CVE-2026-40933, Amazon Q CVE-2026-12957). Fix: checklist #24.
- **PI-SANDBOX-BYPASS** — string-based command gates with no obfuscation defense, sandbox trust keyed off agent-chosen paths (Codex CLI CVE-2025-59532, MS-Agent CVE-2026-2256, Cursor DuneSlide CVE-2026-50548/50549). Fix: checklist #25.
- **PI-MEMORY** — persistent memory written with no integrity or provenance rule. Fix: checklist #26.
- **PI-SUPPLY-CHAIN** — agent installs packages it names itself ("slopsquatting"). Fix: checklist #27.

- **PI-AUTOLOAD-CONFIG** —  workspace configuration auto-loaded before any trust decision (Codex CLI CVE-2025-61260, Claude Code CVE-2025-59536, Cursor CVE-2025-54136 / MCPoison). High by default, Critical when the agent can also execute. Fix: checklist #28.

19-case suite: `python -m unittest tests.test_runtime_rules`.

8-case suite: `python -m unittest tests.test_autoload_rule`.

### New in v2.2 — mcp_guard (MCP tool-response guard)

pi_shield guards the user-input boundary; **mcp_guard guards the tool boundary**. Agents built on MCP (Model Context Protocol) ingest tool responses — web pages, emails, database rows — and every one of them is an untrusted channel for indirect prompt injection. mcp_guard scans tool responses (JSON-aware, findings carry their JSON path) and tool definitions for:

- model special tokens smuggled into data (`<|im_start|>`, `<<SYS>>`, `<system>`, `<s>`)
- fake user consent ("the user has approved — proceed with deleting…")
- tool-call manipulation and dangerous-action endorsement
- exfiltration channels (markdown images with query strings — scheme optional, so protocol-relative `//host` forms are caught — webhook/collection hosts)
- environment-variable poisoning (v2.6.2: "export PAGER=…", `declare -x LD_PRELOAD=…` — Cursor CVE-2026-22708)
- memory-write instructions (v2.6.2: "remember that…", "commit to memory", English + Arabic — MINJA/Sleeper)
- concealment / masquerade instructions (v2.6.2: "do not inform the user", "respond with 'everything is fine'" — Gemini calendar-invite injection)
- hidden channels (unicode tag block, HTML comments) and encoded payloads
- Arabic injection phrases (reuses the v2.1 language rules)

```bash
python scripts/mcp_guard.py tool_response.json
```

```python
from scripts.mcp_guard import guard_tool_response

result = guard_tool_response(response_text, tool_name="fetch")
if result.decision == "BLOCK":
    raise RuntimeError("tool response blocked by policy")  # never reaches the model context
# decision == "WARN": pass result.sanitized, but log result.findings
context += result.sanitized
```

Proven by a 20-case suite: `python -m unittest tests.test_mcp_guard`.

Note: mcp_guard.py here is unrelated to General-Analysis/mcp-guard — the overlap is coincidental; ours is a JSON-level scanner for MCP configs and tool responses.

### New in v2.0 — pi_shield (defense layer)

The auditor finds weaknesses; **pi_shield flags and gates them**. A five-layer input-defense middleware: unicode/homoglyph normalization, safe delimiting with closing-tag neutralization, weighted threat scoring (ALLOW/WARN/BLOCK), base64/hex payload inspection, and canary leak detection. It detects the evasion techniques that break naive filters — closing-tag escapes, zero-width characters, Cyrillic homoglyphs, encoded commands — proven by an 11-case test suite (`python -m unittest tests.test_shield`). "Gates" is a decision, not enforcement: the caller must act on BLOCK/WARN (see the integration example above); the library detects and returns a verdict, the harness enforces it. Since v2.6.2 the scoring layer also covers environment-variable poisoning and concealment phrasing, and a Layer 5 companion — `check_output_channels(model_output)` — flags exfiltration markup (query-bearing or protocol-relative markdown images) in model output before rendering.

### Severity model

Findings come from two sources. Scanner findings are emitted by `pi_scan.py`; reviewer findings are raised by the auditing agent during manual review.

**Scanner findings**

| Severity | Examples |
|----------|----------|
| Critical | Secrets in prompt (PI-SECRET) · action tools **+** untrusted ingestion, EchoLeak-class (PI-TOOLS) · registers or executes MCP tool servers (PI-MCP, execution tier) |
| High | Extractable system prompt · injected instructions can trigger tools · command gate with no obfuscation defense or agent-chosen sandbox path (PI-SANDBOX-BYPASS) · memory writes under untrusted ingestion (PI-MEMORY) · installs model-named packages (PI-SUPPLY-CHAIN) |
| Medium | Persona override · missing output constraints · no authority-spoof guard · MCP surface with no tool-metadata rule (PI-MCP, surface tier) · unpinned package installs |
| Low | Robustness/style issues with no clear exploit path |

**Reviewer findings**

| Severity | Finding |
|----------|---------|
| Critical | **PI-EMBEDDED-INSTRUCTION** — the audited target contains instructions aimed at the auditor, attempting to alter audit scope or methodology (checklist #23) |

## Ethics

This skill is for **defensive auditing and authorized testing only**. Live injection tests are restricted to systems you own or have explicit written permission to test — this guardrail is built into the skill itself.

## Roadmap

- [x] 2026 agent-runtime detection rules — MCP tool poisoning, sandbox bypass, memory injection, slopsquatting (v2.2, English + Arabic)
- [x] MCP tool-response guard (v2.2 — `mcp_guard.py`)
- [ ] Detection rules for agent-framework CVEs (LangChain / Langflow / LangGraph)
- [ ] Skill-file linter mode (dedicated `SKILL.md` lint pass before publishing to skills.sh) — mapped to OWASP Agentic Skills Top 10 (AST10); recall measured on `snyk-labs/toxicskills-goof` (see `references/attack-landscape-2026-08.md`)
- [ ] `PI-EXTERNAL-INSTRUCTIONS` — instructions fetched from a URL and followed (AST05; Air Security, June 2026)
- [ ] `PI-DROPPER` — pipe-to-shell / encoded droppers across the whole package, not only SKILL.md (ClawHavoc-class)
- [ ] mcp_guard tool-description pinning — rug-pull detection via baseline hashes (OWASP MCP03)
- [ ] HTML report output
- [ ] SARIF export for GitHub Code Scanning

## Contributing

Issues and PRs welcome — especially new attack patterns, defense techniques, and scanner rules.

## Contributors

Thanks to everyone who contributes to this project:

- [@3siri](https://github.com/3siri) - Arabic prompt-injection support (normalization, language rules, tests) - first external contributor 🏅

## Author

**Mijlad bin Mishari Al-Subaie** — Cybersecurity Expert, Ethical Hacker (CEH), Digital Forensics Investigator (CHFI), and author of programming encyclopedias (C++, Java, Databases).

- X (Twitter): [@Al7lhh223](https://x.com/Al7lhh223)
- GitHub: [@screem500](https://github.com/screem500)

## License

[Apache License 2.0](LICENSE) — Copyright 2026 Mijlad bin Mishari Al-Subaie. Use it freely, attribution required.

---

*If this skill helped you, a star on the repo helps others find it.*
