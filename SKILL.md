---
name: prompt-injection-auditor
description: >
  Security audit of LLM system prompts, agent instruction files (SKILL.md,
  AGENTS.md, CLAUDE.md), and agent configurations against prompt injection
  attacks. Use when the user wants to (1) audit or harden a system prompt or
  agent instructions against prompt injection, (2) review an agent skill or
  system prompt for security weaknesses before publishing, (3) generate a
  prompt-injection risk report with severity ratings and fixes, (4) run
  authorized red-team tests against an LLM agent they own or are permitted
  to test, or (5) check for data-leakage risks such as exposed secrets,
  weak instruction hierarchy, or missing output constraints.
---

# Prompt Injection Auditor

## Overview

Audit LLM system prompts and agent instruction files for prompt-injection weaknesses, then produce a severity-rated report with concrete fixes. Combines a deterministic static scanner with structured manual review and an authorized live-testing playbook.

## Ethics and Scope

Run live injection tests **only** against systems the user owns or has explicit written permission to test. Static analysis of files the user provides is always in scope. If the target is a third-party production system without authorization, refuse live testing and limit work to defensive review.

## Workflow

### Step 1: Collect the target

Obtain one or more of: the system prompt text, agent instruction files (`SKILL.md`, `AGENTS.md`, `CLAUDE.md`, `.cursorrules`), tool/permission configuration, or a description of the agent's capabilities (tools, data access, retrieval sources).

### Step 2: Run the static scan

```bash
python scripts/pi_scan.py <target-file> [--json report.json] [--md report.md]
```

The scanner checks for ~20 weakness classes (missing instruction hierarchy, secret-like strings, leak-prone phrasing, missing output constraints, untrusted-content handling gaps) and outputs a 0–100 risk score with findings. Treat scanner output as leads, not verdicts — verify each finding by reading the target.

### Step 3: Manual review with the attack catalog

Read `references/attack-patterns.md` and map the target against each relevant category:

- Direct injection resistance (override, persona, translation/encoding tricks)
- Indirect injection surface (does the agent ingest web pages, emails, files, tool output?)
- Exfiltration channels (markdown images, links, tool calls that send data out)
- Privilege boundaries (what can the agent *do*: send messages, run code, call APIs?)
- Cross-agent trust (multi-agent setups where one agent's output feeds another)

Flag every capability that an injected instruction could abuse. A prompt with no tools can only leak text; a prompt with tools can take actions — rate severity accordingly.

### Step 4: Live testing (authorized targets only)

If the user has an authorized live target, use the payloads in `references/test-payloads.md`:

1. Start with the baseline canary test to confirm the agent is reachable and responsive.
2. Run categories in order: extraction → override → indirect → exfiltration.
3. Record exact prompt, response, and whether the defense held for each test.
4. Stop after any test that causes real-world side effects; report instead of escalating.

### Step 5: Report

Produce a report with: executive summary, risk score, findings table (ID, severity, description, evidence, fix), and a hardened rewrite of the prompt when requested. Use `references/defense-checklist.md` as the source for fixes — map every finding to a checklist item.

Severity guide:

- **Critical**: secrets/keys present in prompt; agent can send data out AND ingests untrusted content (EchoLeak-class).
- **High**: system prompt fully extractable; injected instructions can trigger tool actions.
- **Medium**: persona override succeeds; missing output constraints; weak refusal behavior.
- **Low**: style/robustness issues with no clear exploit path.

## Resources

### scripts/
- `pi_scan.py` — Static analyzer for system prompts and instruction files. No dependencies; Python 3.8+. Outputs findings with line numbers, risk score, and optional JSON/Markdown reports.
- `pi_shield.py` — Layered prompt-injection *defense* (v2.0): normalization, safe delimiting with closing-tag neutralization, scored detection, encoded-payload inspection, canary output check. Use when the user wants to add input protection to an agent, not just audit it. Prove with `test_shield.py` (11 cases).
- `test_shield.py` — Test suite proving pi_shield against evasion techniques (homoglyphs, zero-width, base64, delimiter escape). Run after any shield change.

### references/
- `attack-patterns.md` — Catalog of prompt-injection techniques (direct, indirect, encoding, exfiltration, multi-agent) with real-world examples. Read during Step 3.
- `defense-checklist.md` — Actionable hardening measures; each item maps to a finding class. Read during Step 5.
- `defense-architecture.md` — The 5-layer defense design behind pi_shield, usage patterns, and honest limits of prompt-level filtering. Read when implementing input protection.
- `test-payloads.md` — Organized payload suite for authorized live testing, ordered by escalation. Read during Step 4.
