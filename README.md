# prompt-injection-auditor

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Agent Skills](https://img.shields.io/badge/Agent%20Skills-agentskills.io-green)](https://agentskills.io)
[![Install](https://img.shields.io/badge/npx-skills%20add-orange)](https://skills.sh)

**An open Agent Skill that turns any AI agent into a prompt-injection security auditor.**
Static scanner + attack catalog + defense checklist + authorized red-team payloads — built against real-world incidents like EchoLeak (CVE-2025-32711).

Works with Claude Code, Cursor, Kimi, and 20+ agents that support the open Agent Skills https://agentskills.io standard.

![live demo](demo-prompt-injection-auditor.gif)
## Why?

Research evaluations in 2025 found that **over 90% of production LLM agents are susceptible to prompt injection**, and real incidents keep proving it:

- **EchoLeak (CVE-2025-32711, CVSS 9.3)** — the first zero-click prompt injection in a production AI system: hidden instructions in an email made Microsoft 365 Copilot exfiltrate OneDrive/SharePoint data via a markdown image, no clicks needed.
- **LangGrinch (CVE-2025-68664)** — LangChain serialization injection leaking environment secrets through model responses.
- **Langflow (CVE-2025-3248 / CVE-2026-33017)** — unauthenticated RCE in an agent-building framework, exploited within hours of disclosure.

Most system prompts ship with no instruction hierarchy, no non-disclosure rule, and no untrusted-content handling. This skill finds those weaknesses before attackers do.

## Install

```bash
npx skills add <your-username>/prompt-injection-auditor
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

## What's inside

```
prompt-injection-auditor/
├── SKILL.md                        # 5-step audit methodology + ethics guardrails
├── scripts/
│   └── pi_scan.py                  # Zero-dependency static analyzer (~20 weakness classes)
└── references/
    ├── attack-patterns.md          # Direct / indirect / encoding / exfiltration / multi-agent
    ├── defense-checklist.md        # 22 numbered hardening measures
    └── test-payloads.md            # Escalation-ordered payloads for authorized live tests
```

### Severity model

| Severity | Examples |
|----------|----------|
| Critical | Secrets in prompt · action tools **+** untrusted ingestion (EchoLeak-class) |
| High | Extractable system prompt · injected instructions can trigger tools |
| Medium | Persona override · missing output constraints · no authority-spoof guard |
| Low | Robustness/style issues with no clear exploit path |

## Ethics

This skill is for **defensive auditing and authorized testing only**. Live injection tests are restricted to systems you own or have explicit written permission to test — this guardrail is built into the skill itself.

## Roadmap

- [ ] Detection rules for the latest agent-framework CVEs (LangChain / Langflow / LangGraph)
- [ ] Skill-file linter mode (audit `SKILL.md` files before publishing to skills.sh)
- [ ] HTML report output
- [ ] SARIF export for GitHub Code Scanning

## Contributing

Issues and PRs welcome — especially new attack patterns, defense techniques, and scanner rules.

Author
Mijlad bin Mishari Al-Subaie — Cybersecurity Expert, Ethical Hacker (CEH), Digital Forensics Investigator (CHFI), and author of programming encyclopedias (C++, Java, Databases).
•  X (Twitter): @Al7lhh223 https://x.com/Al7lhh223
•  GitHub: @screem500 https://github.com/screem500

## License 

[Apache License 2.0](LICENSE) — Copyright 2026. Use it freely, attribution required.

---

*If this skill helped you, a star on the repo helps others find it.*
