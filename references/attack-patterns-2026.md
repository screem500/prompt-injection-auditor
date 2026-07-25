# Attack Patterns — 2026 Agent-Runtime Families

The original `attack-patterns.md` catalog covers prompt-level injection. In 2026 the dominant incidents moved one layer down: into the agent **runtime** — tool servers, sandboxes, memory, and package installation. This file documents the four families behind pi_scan's PI-MCP, PI-SANDBOX-BYPASS, PI-MEMORY, and PI-SUPPLY-CHAIN rules, each anchored to disclosed CVEs.

## Contents

- [1. MCP tool-server exposure (PI-MCP)](#1-mcp-tool-server-exposure-pi-mcp)
- [2. Sandbox / allowlist bypass (PI-SANDBOX-BYPASS)](#2-sandbox--allowlist-bypass-pi-sandbox-bypass)
- [3. Persistent memory injection (PI-MEMORY)](#3-persistent-memory-injection-pi-memory)
- [4. Supply-chain slopsquatting (PI-SUPPLY-CHAIN)](#4-supply-chain-slopsquatting-pi-supply-chain)

## 1. MCP tool-server exposure (PI-MCP)

Adding a tool server is a code-execution primitive. A stdio MCP configuration is a launcher definition: it names a binary, arguments, and environment. If injected content — or a lower-trust user, or a poisoned repository — can reach the server-add path, that is RCE by proxy.

Documented anchors:

- **CVE-2026-40933 — Flowise Custom MCP (CVSS 9.9).** Unsafe serialization of stdio commands in the MCP adapter: an authenticated user could register an MCP server whose allowlisted command (`npx`) combined with execution arguments (`-c`) ran arbitrary OS commands. Fixed in 3.1.0; researchers still advise disabling stdio MCP in production.
- **CVE-2026-12957 / CVE-2026-12958 — Amazon Q Developer (Wiz Research).** The extension auto-loaded MCP server configs from `.amazonq/mcp.json` inside any opened repository, without consent or trust checks, with full environment inheritance — one malicious repo leaked AWS session credentials. No clicks, no prompts.
- **CVE-2025-61260 — Codex CLI (CVSS 9.8).** Running `codex` inside a malicious repository auto-loaded project-local `.env` and `.codex/config.toml` files, executing embedded MCP config commands immediately.

Scanner logic: MCP surface present → Medium; agent can register/connect servers → High; mutable **and** (execution capability or unsafe stdio/serialization) → Critical.

Defenses: pinned allowlist of known servers, human confirmation before any server add, tool metadata treated as data with no authority (Checklist #5, #9, #10).

## 2. Sandbox / allowlist bypass (PI-SANDBOX-BYPASS)

Command gates that match on strings lose to obfuscation; trust decisions that key off agent-influenced paths lose to redirection.

Documented anchors:

- **CVE-2026-2256 — ModelScope MS-Agent (CVSS 6.5, CERT VU#431821).** The Shell tool's `check_safe()` used a regex **denylist** — a known-unsafe pattern. Crafted prompt-derived content bypassed six validation layers and executed as attacker logic, via trusted interpreters and shell parsing semantics. No vendor response during coordination.
- **CVE-2026-50548 + CVE-2026-50549 — Cursor "DuneSlide" (CVSS 9.8 / 9.3 on v4).** Zero-click: hidden instructions in an MCP response or web page steered the agent into (a) setting `working_directory` to a sensitive path — which Cursor silently added to the writable allowlist — or (b) writing through a symlink when path canonicalization failed and fell back to trusting the symlink. Both overwrote the `cursorsandbox` helper, turning every later command into unsandboxed RCE.
- **CVE-2025-59532 — Codex CLI.** A sandbox-configuration bug treated a **model-generated cwd** as the sandbox's writable root, including paths outside the session folder. Fixed in 0.39.0 by basing the boundary on where the user started, not where the model said.

Scanner logic: execution capability + allow/deny-list gate with no stated obfuscation defense → High; execution capability + sandbox/trust decision keyed off working directory or environment → High.

Defenses: gate on parsed intent, canonicalize before matching, the enforcer (never the agent) owns cwd and environment (Checklist #13, #17).

## 3. Persistent memory injection (PI-MEMORY)

An instruction injected once and written to long-term memory replays in **every future session** with system-prompt authority. This is the persistence layer of indirect injection: one poisoned web page today becomes a permanent behavioral change.

No single CVE anchors this class yet — it is a design weakness, like missing instruction hierarchy was in 2025. The attack shape: retrieval carries "remember X" → agent stores X verbatim → X is reloaded as trusted context forever.

Scanner logic: persistent-memory feature present without an integrity/provenance guard → Medium; the same under untrusted ingestion → High.

Defenses: memory content is data, never instructions; provenance on every write; review before replay; no memory sharing across users (Checklist #5, #15).

## 4. Supply-chain slopsquatting (PI-SUPPLY-CHAIN)

Models hallucinate package names **predictably** — the same plausible-but-wrong names recur across users and sessions. Attackers pre-register those names on npm/PyPI, seed them with malicious code (plus hidden injection payloads for the next agent that reads them), and wait for a coding agent to `pip install` the attacker copy on its own authority.

This family is documented as a research class ("slopsquatting", package-hallucination attacks) rather than a single CVE; the same trust failure — executing what a model names without verification — appears in the repo-borne config incidents above (Codex CLI CVE-2025-61260, Amazon Q CVE-2026-12957).

Scanner logic: execution capability + install/fetch behavior with no name pinning → Medium; the prompt explicitly has the model pick the package name ("install the right package") → High.

Defenses: never install a model-produced identifier; pin names, verify against lockfiles or known-good indexes, human-approve installs (Checklist #10, #17).

---

*Every CVE above was verified against NVD/GitHub advisories/CERT at the time of writing. Scores are CVSS 3.1 unless noted (DuneSlide: 9.3 on CVSS 4.0). Static rules find leads, not verdicts — confirm each finding manually.*
