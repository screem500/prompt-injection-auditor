#!/usr/bin/env python3
"""pi_scan.py — Static prompt-injection weakness scanner for system prompts
and agent instruction files (SKILL.md, AGENTS.md, CLAUDE.md, .cursorrules).

No third-party dependencies. Python 3.8+.

Usage:
    python pi_scan.py <target-file> [--json report.json] [--md report.md]
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

from .rules.registry import (
    EXEC_TOOL_PATTERN, HIERARCHY_PATTERNS, INGEST_KEYWORDS, LEAK_PRONE_PATTERNS,
    MCP_MUTABLE_PATTERN, MCP_PRESENT_PATTERN, MCP_UNSAFE_PATTERN, MEMORY_GUARD_PATTERN,
    MEMORY_PATTERN, NONDISCLOSURE_PATTERNS, OUTPUT_CONSTRAINT_PATTERNS, REFUSAL_PATTERNS,
    ROLE_CLAIM_PATTERNS, SANDBOX_BYPASS_AWARE_PATTERN, SANDBOX_GATE_PATTERN,
    SANDBOX_WORKDIR_PATTERN, SECRET_PATTERNS, SUPPLY_CHAIN_FETCH_PATTERN,
    SUPPLY_CHAIN_MODEL_NAMED_PATTERN, TOOL_RISK_KEYWORDS, UNTRUSTED_CONTENT_PATTERNS,
)
from .findings import Finding
from .scoring import STATIC_AUDIT_POLICY, calculate_score, static_verdict


from .languages import get_language_pack, resolve_language_packs

_ARABIC_PACK = get_language_pack("ar")
normalize_arabic = _ARABIC_PACK.normalize
suspicious_unicode_lines = _ARABIC_PACK.get("suspicious_unicode_lines")
ARABIC_DEFENSIVE_CONTEXT_PATTERNS = _ARABIC_PACK.defensive_context_patterns
ARABIC_INJECTION_PATTERNS = _ARABIC_PACK.attack_rules
ARABIC_HIERARCHY_PATTERNS = _ARABIC_PACK.get("hierarchy_patterns")
ARABIC_INGEST_KEYWORDS = _ARABIC_PACK.get("ingest_keywords")
ARABIC_MCP_MUTABLE_PATTERNS = _ARABIC_PACK.get("mcp_mutable_patterns")
ARABIC_MCP_PRESENT_PATTERNS = _ARABIC_PACK.get("mcp_present_patterns")
ARABIC_MEMORY_GUARD_PATTERNS = _ARABIC_PACK.get("memory_guard_patterns")
ARABIC_MEMORY_PATTERNS = _ARABIC_PACK.get("memory_patterns")
ARABIC_NONDISCLOSURE_PATTERNS = _ARABIC_PACK.get("nondisclosure_patterns")
ARABIC_OUTPUT_CONSTRAINT_PATTERNS = _ARABIC_PACK.get("output_constraint_patterns")
ARABIC_REFUSAL_PATTERNS = _ARABIC_PACK.get("refusal_patterns")
ARABIC_ROLE_CLAIM_PATTERNS = _ARABIC_PACK.get("role_claim_patterns")
ARABIC_SUPPLY_CHAIN_FETCH_PATTERNS = _ARABIC_PACK.get("supply_chain_fetch_patterns")
ARABIC_TOOL_RISK_KEYWORDS = _ARABIC_PACK.get("tool_risk_keywords")
ARABIC_UNTRUSTED_CONTENT_PATTERNS = _ARABIC_PACK.get("untrusted_content_patterns")

_RUSSIAN_PACK = get_language_pack("ru")
normalize_russian = _RUSSIAN_PACK.normalize
RUSSIAN_DEFENSIVE_CONTEXT_PATTERNS = _RUSSIAN_PACK.defensive_context_patterns
RUSSIAN_INJECTION_PATTERNS = _RUSSIAN_PACK.attack_rules
RUSSIAN_HIERARCHY_PATTERNS = _RUSSIAN_PACK.get("hierarchy_patterns")
RUSSIAN_INGEST_KEYWORDS = _RUSSIAN_PACK.get("ingest_keywords")
RUSSIAN_MCP_MUTABLE_PATTERNS = _RUSSIAN_PACK.get("mcp_mutable_patterns")
RUSSIAN_MCP_PRESENT_PATTERNS = _RUSSIAN_PACK.get("mcp_present_patterns")
RUSSIAN_MEMORY_GUARD_PATTERNS = _RUSSIAN_PACK.get("memory_guard_patterns")
RUSSIAN_MEMORY_PATTERNS = _RUSSIAN_PACK.get("memory_patterns")
RUSSIAN_NONDISCLOSURE_PATTERNS = _RUSSIAN_PACK.get("nondisclosure_patterns")
RUSSIAN_OUTPUT_CONSTRAINT_PATTERNS = _RUSSIAN_PACK.get("output_constraint_patterns")
RUSSIAN_REFUSAL_PATTERNS = _RUSSIAN_PACK.get("refusal_patterns")
RUSSIAN_ROLE_CLAIM_PATTERNS = _RUSSIAN_PACK.get("role_claim_patterns")
RUSSIAN_SUPPLY_CHAIN_FETCH_PATTERNS = _RUSSIAN_PACK.get("supply_chain_fetch_patterns")
RUSSIAN_TOOL_RISK_KEYWORDS = _RUSSIAN_PACK.get("tool_risk_keywords")
RUSSIAN_UNTRUSTED_CONTENT_PATTERNS = _RUSSIAN_PACK.get("untrusted_content_patterns")


def _supports_color():
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


_COLOR = _supports_color()
RED_BOLD, RED, YELLOW, CYAN, GREEN, GRAY, BOLD = "91;1", "91", "93", "96", "92", "90", "1"
SEVERITY_COLOR = {"Critical": RED_BOLD, "High": RED, "Medium": YELLOW, "Low": CYAN}


def paint(text, code):
    return f"\033[{code}m{text}\033[0m" if _COLOR else text




# --- 2026 agent-runtime rule patterns ---------------------------------------
# Covers weakness classes that became dominant after the original ~20 rule
# families were written: MCP tool-server exposure, sandbox/allowlist bypass,
# persistent memory injection, and supply-chain slopsquatting. Each anchors
# to a disclosed 2026 CVE — see references/attack-patterns-2026.md.







def find_lines(text, pattern, skip_context_patterns=None):
    """Return 1-based matching lines, optionally excluding local safe contexts.

    Suppression is evaluated around each candidate match rather than across the
    entire line. This prevents an unrelated defensive phrase elsewhere on a long
    line from hiding a real injection pattern.
    """

    rx = re.compile(pattern)
    skip_patterns = [re.compile(item) for item in (skip_context_patterns or [])]
    lines = []
    for index, line in enumerate(text.splitlines(), start=1):
        for match in rx.finditer(line):
            start = max(0, match.start() - 140)
            end = min(len(line), match.end() + 60)
            context = line[start:end]
            if not any(skip.search(context) for skip in skip_patterns):
                lines.append(index)
                break
    return lines


def _has_any(text, patterns):
    return any(re.search(pattern, text) for pattern in patterns)


def _scan_legacy(text):
    findings = []
    low = text.lower()
    normalized_ar = normalize_arabic(text).lower()
    normalized_ru = normalize_russian(text).lower()

    for pattern, label in SECRET_PATTERNS:
        lines = find_lines(text, pattern)
        if lines:
            findings.append({
                "id": "PI-SECRET", "severity": "Critical",
                "title": f"Secret-like value present: {label}", "lines": lines,
                "detail": "Credentials in prompts must be considered compromised. Prompts leak.",
                "fix": "Remove all credentials. Rotate the exposed secret. Load secrets from a vault/environment at runtime, never from prompt text. (Checklist #6)",
            })

    for pattern, label in LEAK_PRONE_PATTERNS:
        lines = find_lines(text, pattern)
        if lines:
            findings.append({
                "id": "PI-LEAKPHRASE", "severity": "High",
                "title": f"Leak-prone phrasing: {label}", "lines": lines,
                "detail": "Wording in the prompt itself invites or normalizes disclosure of instructions or unrestricted behavior.",
                "fix": "Remove the clause; replace with an explicit non-disclosure rule. (Checklist #2, #7)",
            })

    invisible_lines = suspicious_unicode_lines(text)
    if invisible_lines:
        findings.append({
            "id": "PI-UNICODE-OBFUSCATION", "severity": "Medium",
            "title": "Suspicious zero-width or bidirectional Unicode controls",
            "lines": invisible_lines,
            "detail": "Invisible formatting controls can hide or visually reorder injected instructions during review.",
            "fix": "Normalize input before matching, display escaped code points in review logs, and reject unexpected direction controls. (Checklist #13, #19)",
        })

    for rule in ARABIC_INJECTION_PATTERNS:
        matched_lines = sorted({
            line
            for pattern in rule["patterns"]
            for line in find_lines(normalized_ar, pattern, ARABIC_DEFENSIVE_CONTEXT_PATTERNS)
        })
        if matched_lines:
            findings.append({
                "id": rule["id"], "severity": rule["severity"],
                "title": rule["title"], "lines": matched_lines,
                "detail": rule["detail"], "fix": rule["fix"],
            })

    for rule in RUSSIAN_INJECTION_PATTERNS:
        matched_lines = sorted({
            line
            for pattern in rule["patterns"]
            for line in find_lines(normalized_ru, pattern, RUSSIAN_DEFENSIVE_CONTEXT_PATTERNS)
        })
        if matched_lines:
            findings.append({
                "id": rule["id"], "severity": rule["severity"],
                "title": rule["title"], "lines": matched_lines,
                "detail": rule["detail"], "fix": rule["fix"],
            })

    tool_hits = []
    ingest_lines = []
    for pattern, label in TOOL_RISK_KEYWORDS:
        lines = find_lines(text, pattern)
        if lines:
            tool_hits.append((label, lines))
    for pattern, label in ARABIC_TOOL_RISK_KEYWORDS:
        lines = find_lines(normalized_ar, pattern)
        if lines:
            tool_hits.append((label, lines))
    for pattern, label in RUSSIAN_TOOL_RISK_KEYWORDS:
        lines = find_lines(normalized_ru, pattern)
        if lines:
            tool_hits.append((label, lines))
    for pattern in INGEST_KEYWORDS:
        ingest_lines.extend(find_lines(text, pattern))
    for pattern in ARABIC_INGEST_KEYWORDS:
        ingest_lines.extend(find_lines(normalized_ar, pattern))
    for pattern in RUSSIAN_INGEST_KEYWORDS:
        ingest_lines.extend(find_lines(normalized_ru, pattern))
    ingest_lines = sorted(set(ingest_lines))

    if tool_hits:
        labels = "; ".join(sorted({label for label, _ in tool_hits}))
        all_lines = sorted({line for _, lines in tool_hits for line in lines})
        severity = "Critical" if ingest_lines else "High"
        findings.append({
            "id": "PI-TOOLS", "severity": severity,
            "title": f"Powerful capabilities declared: {labels}", "lines": all_lines,
            "detail": (
                "The agent has action capabilities"
                + (" AND ingests untrusted content (web/email/RAG) — one injected instruction can act with the agent's privileges."
                   if ingest_lines else
                   " — an injected instruction that overrides the prompt inherits these privileges.")
            ),
            "fix": "Apply least privilege, require human confirmation for consequential actions, and filter egress. (Checklist #9, #10, #11)",
        })
    elif ingest_lines:
        findings.append({
            "id": "PI-INGEST", "severity": "Medium",
            "title": "Agent ingests untrusted content (web/email/files/RAG)", "lines": ingest_lines,
            "detail": "Retrieved content is an indirect-injection vector even without powerful tools.",
            "fix": "Mark retrieved content as inert data with delimiters; never treat it as instructions. (Checklist #5, #14)",
        })

    # has_exec reuses tool_hits (already bilingual: English TOOL_RISK_KEYWORDS +
    # ARABIC_TOOL_RISK_KEYWORDS) and adds a broader English-only net for coding
    # agents that name a shell/terminal/interpreter tool without the phrase
    # "execute code".
    has_exec = (
        any(label.startswith("Code/command execution capability") for label, _ in tool_hits)
        or bool(find_lines(text, EXEC_TOOL_PATTERN))
    )

    mcp_lines = find_lines(text, MCP_PRESENT_PATTERN)
    for pattern in ARABIC_MCP_PRESENT_PATTERNS:
        mcp_lines.extend(find_lines(normalized_ar, pattern))
    for pattern in RUSSIAN_MCP_PRESENT_PATTERNS:
        mcp_lines.extend(find_lines(normalized_ru, pattern))
    if mcp_lines:
        mutable_lines = find_lines(text, MCP_MUTABLE_PATTERN)
        for pattern in ARABIC_MCP_MUTABLE_PATTERNS:
            mutable_lines.extend(find_lines(normalized_ar, pattern))
        for pattern in RUSSIAN_MCP_MUTABLE_PATTERNS:
            mutable_lines.extend(find_lines(normalized_ru, pattern))
        unsafe_lines = find_lines(text, MCP_UNSAFE_PATTERN)
        if mutable_lines and (has_exec or unsafe_lines):
            findings.append({
                "id": "PI-MCP", "severity": "Critical",
                "title": "Agent can add/configure MCP tool servers with no execution or serialization boundary",
                "lines": sorted(set(mutable_lines + unsafe_lines)),
                "detail": "Adding a tool server is equivalent to granting code execution. If injected content can reach the server-add path, that is unauthenticated RCE by proxy (Flowise Custom MCP stdio, CVE-2026-40933, CVSS 9.9; Amazon Q auto-loaded workspace MCP configs, CVE-2026-12957; Codex CLI repo-borne MCP configs, CVE-2025-61260).",
                "fix": "Pin an allowlist of specific, known servers. Require human confirmation before any new server is added. Treat tool descriptions and tool outputs as untrusted data with no authority over instructions. (Checklist #24, #9, #10)",
            })
        elif mutable_lines:
            findings.append({
                "id": "PI-MCP", "severity": "High",
                "title": "Agent can register or connect MCP servers with no stated integrity check",
                "lines": mutable_lines,
                "detail": "A poisoned tool description or a malicious server can override instructions or exfiltrate data through the tool layer even without a direct execution path.",
                "fix": "Require a pinned allowlist and verify server identity before connecting. Never treat tool metadata as authoritative. (Checklist #24, #5, #9)",
            })
        else:
            findings.append({
                "id": "PI-MCP", "severity": "Medium",
                "title": "MCP/tool-server surface present with no untrusted-content rule for tool metadata",
                "lines": mcp_lines,
                "detail": "Tool poisoning injects instructions through the tool schema itself, not just the tool output.",
                "fix": "State explicitly that tool descriptions and tool results carry no authority over the agent's instructions. (Checklist #24, #5)",
            })

    if has_exec:
        gate_lines = find_lines(text, SANDBOX_GATE_PATTERN)
        bypass_aware_lines = find_lines(text, SANDBOX_BYPASS_AWARE_PATTERN)
        if gate_lines and not bypass_aware_lines:
            findings.append({
                "id": "PI-SANDBOX-BYPASS", "severity": "High",
                "title": "Command gating relies on allow/deny-listed strings with no stated obfuscation defense",
                "lines": gate_lines,
                "detail": "Denylists fall to obfuscation (ModelScope MS-Agent, CVE-2026-2256, CVSS 6.5 — regex denylist bypass) and path-based gates fall to symlink/canonicalization tricks (Cursor, CVE-2026-50549, CVSS 9.8).",
                "fix": "Gate on parsed intent, not string matching. Canonicalize and normalize input before any allow/deny decision. (Checklist #25, #13, #17)",
            })

        workdir_lines = find_lines(text, SANDBOX_WORKDIR_PATTERN)
        if workdir_lines:
            findings.append({
                "id": "PI-SANDBOX-BYPASS", "severity": "High",
                "title": "Sandbox or trust decision keys off a path or environment variable the agent can influence",
                "lines": workdir_lines,
                "detail": "Letting the agent's own output or working-directory choice influence the sandbox boundary lets injected content redefine that boundary (Cursor DuneSlide, CVE-2026-50548, CVSS 9.8; Codex CLI, CVE-2025-59532 — model-generated cwd became the sandbox root).",
                "fix": "The enforcer, never the agent, owns the working directory and environment. Validate both outside the agent's influence. (Checklist #25, #17)",
            })

    memory_lines = find_lines(text, MEMORY_PATTERN)
    for pattern in ARABIC_MEMORY_PATTERNS:
        memory_lines.extend(find_lines(normalized_ar, pattern))
    for pattern in RUSSIAN_MEMORY_PATTERNS:
        memory_lines.extend(find_lines(normalized_ru, pattern))
    memory_guarded = find_lines(text, MEMORY_GUARD_PATTERN)
    for pattern in ARABIC_MEMORY_GUARD_PATTERNS:
        memory_guarded.extend(find_lines(normalized_ar, pattern))
    for pattern in RUSSIAN_MEMORY_GUARD_PATTERNS:
        memory_guarded.extend(find_lines(normalized_ru, pattern))
    if memory_lines and not memory_guarded:
        findings.append({
            "id": "PI-MEMORY", "severity": "High" if ingest_lines else "Medium",
            "title": "Persistent memory is written with no integrity or provenance rule",
            "lines": memory_lines,
            "detail": "An instruction injected once and stored in long-term memory persists into every future session, replayed with the same authority as the system prompt.",
            "fix": "State that memory content is data, never instructions. Do not write untrusted content to memory verbatim; attach provenance and review before replay. (Checklist #26, #5, #15)",
        })

    if has_exec:
        fetch_lines = find_lines(text, SUPPLY_CHAIN_FETCH_PATTERN)
        for pattern in ARABIC_SUPPLY_CHAIN_FETCH_PATTERNS:
            fetch_lines.extend(find_lines(normalized_ar, pattern))
        for pattern in RUSSIAN_SUPPLY_CHAIN_FETCH_PATTERNS:
            fetch_lines.extend(find_lines(normalized_ru, pattern))
        if fetch_lines:
            model_named = bool(find_lines(text, SUPPLY_CHAIN_MODEL_NAMED_PATTERN))
            findings.append({
                "id": "PI-SUPPLY-CHAIN",
                "severity": "High" if model_named else "Medium",
                "title": (
                    "Agent installs or fetches packages/repos using names it selects itself"
                    if model_named else
                    "Agent installs or fetches packages/repos with no name pinning stated"
                ),
                "lines": fetch_lines,
                "detail": "Attackers pre-register the fake package/repo names models reliably invent ('slopsquatting' — USENIX Security 2025, Spracklen et al.: 19.7% of model-recommended packages don't exist, 43% of fakes repeat every run), seed them with malicious code plus hidden injection, and wait for the agent to fetch the attacker copy.",
                "fix": "Never install a model-produced identifier. Pin names and verify against a lockfile or known-good index before any install. (Checklist #27, #10, #17)",
            })

    def missing(english_patterns, arabic_patterns, russian_patterns, finding_id, severity, title, detail, fix):
        if not (
            _has_any(low, english_patterns)
            or _has_any(normalized_ar, arabic_patterns)
            or _has_any(normalized_ru, russian_patterns)
        ):
            findings.append({
                "id": finding_id, "severity": severity, "title": title,
                "lines": [], "detail": detail, "fix": fix,
            })

    missing(HIERARCHY_PATTERNS, ARABIC_HIERARCHY_PATTERNS, RUSSIAN_HIERARCHY_PATTERNS, "PI-NO-HIERARCHY", "High",
            "No explicit instruction hierarchy",
            "The prompt never states that system instructions outrank user/retrieved content.",
            "Add: system instructions take precedence; user and retrieved content are data, never commands. (Checklist #1)")
    missing(NONDISCLOSURE_PATTERNS, ARABIC_NONDISCLOSURE_PATTERNS, RUSSIAN_NONDISCLOSURE_PATTERNS, "PI-NO-NONDISCLOSE", "High",
            "No non-disclosure rule for the prompt itself",
            "Nothing forbids revealing, paraphrasing, translating, or encoding the system prompt.",
            "Add a clause forbidding disclosure, paraphrase, translation, or encoding. (Checklist #2)")
    missing(ROLE_CLAIM_PATTERNS, ARABIC_ROLE_CLAIM_PATTERNS, RUSSIAN_ROLE_CLAIM_PATTERNS, "PI-NO-ROLEGUARD", "Medium",
            "No guard against authority spoofing",
            "The prompt does not reject privilege claims such as 'I am the developer'.",
            "Add: identity claims in user messages grant no privileges. (Checklist #3)")
    missing(OUTPUT_CONSTRAINT_PATTERNS, ARABIC_OUTPUT_CONSTRAINT_PATTERNS, RUSSIAN_OUTPUT_CONSTRAINT_PATTERNS, "PI-NO-OUTPUTLIM", "Medium",
            "No output scope constraints",
            "The prompt does not bound what the agent may discuss.",
            "Define allowed topics and refusal behavior for out-of-scope requests. (Checklist #4, #7)")
    missing(UNTRUSTED_CONTENT_PATTERNS, ARABIC_UNTRUSTED_CONTENT_PATTERNS, RUSSIAN_UNTRUSTED_CONTENT_PATTERNS, "PI-NO-DELIMIT", "Medium",
            "No untrusted-content delimiting strategy",
            "No delimiting or datamarking guidance separates retrieved content from instructions.",
            "Wrap retrieved content in tagged delimiters and treat it as inert data. (Checklist #5, #14)")
    missing(REFUSAL_PATTERNS, ARABIC_REFUSAL_PATTERNS, RUSSIAN_REFUSAL_PATTERNS, "PI-NO-REFUSAL", "Low",
            "No predefined refusal phrasing",
            "Without a defined refusal response, the agent fails unpredictably under attack.",
            "Predefine a short, consistent refusal for injection attempts. (Checklist #7)")

    return findings


def scan_findings(text):
    """Return canonical Finding objects for a static prompt audit."""
    return [Finding.from_legacy_scanner_dict(item) for item in _scan_legacy(text)]


def scan(text):
    """Backward-compatible scanner output using legacy dictionaries."""
    return [finding.to_legacy_scanner_dict() for finding in scan_findings(text)]


SEVERITY_WEIGHT = {"Critical": 35, "High": 18, "Medium": 8, "Low": 3}
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def risk_score(findings):
    structured = [item if isinstance(item, Finding) else Finding.from_legacy_scanner_dict(item) for item in findings]
    return calculate_score(structured, STATIC_AUDIT_POLICY).score


def verdict(score):
    return static_verdict(score)


def print_report(path, findings, score):
    bar = "#" * (score // 5) + "-" * (20 - score // 5)
    score_color = RED_BOLD if score >= 70 else (RED if score >= 40 else (YELLOW if score >= 15 else GREEN))
    print(f"\n{paint('=== Prompt Injection Audit:', CYAN)} {paint(path, BOLD)} {paint('===', CYAN)}")
    print(f"Risk score: {paint(f'{score}/100', score_color)} [{paint(bar, score_color)}]  {paint(verdict(score), score_color)}\n")
    if not findings:
        print(paint("No findings. Note: static analysis cannot prove safety — run live tests for confirmation.", GREEN))
        return
    for finding in sorted(findings, key=lambda item: SEVERITY_ORDER[item["severity"]]):
        severity = finding["severity"]
        location = f" (lines {', '.join(map(str, finding['lines']))})" if finding["lines"] else ""
        print(f"{paint('[' + f'{severity:>8}' + ']', SEVERITY_COLOR.get(severity, BOLD))} {paint(finding['id'], BOLD)}: {finding['title']}{paint(location, GRAY)}")
        print(f"           {paint('Why:', GRAY)} {finding['detail']}")
        print(f"           {paint('Fix:', GREEN)} {finding['fix']}\n")
    counts = {}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    summary = ", ".join(
        paint(f"{key}={counts[key]}", SEVERITY_COLOR.get(key, BOLD))
        for key in ("Critical", "High", "Medium", "Low") if key in counts
    )
    print(f"{paint('Summary:', BOLD)} {summary}")


def to_json(path, findings, score):
    structured = [item if isinstance(item, Finding) else Finding.from_legacy_scanner_dict(item) for item in findings]
    scoring = calculate_score(structured, STATIC_AUDIT_POLICY)
    return {
        "tool": "pi_scan (prompt-injection-auditor skill)",
        "schema_version": "3.0",
        "target": path,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "risk_score": score,
        "verdict": verdict(score),
        "scoring": scoring.to_dict(),
        "findings": [finding.to_legacy_scanner_dict() for finding in structured],
        "structured_findings": [finding.to_dict() for finding in structured],
    }


def to_markdown(path, findings, score):
    lines = [
        f"# Prompt Injection Audit — `{path}`", "",
        f"**Risk score:** {score}/100 — {verdict(score)}", "",
        "| ID | Severity | Finding | Location | Fix |",
        "|----|----------|---------|----------|-----|",
    ]
    for finding in sorted(findings, key=lambda item: SEVERITY_ORDER[item["severity"]]):
        location = ", ".join(map(str, finding["lines"])) if finding["lines"] else "—"
        lines.append(f"| {finding['id']} | {finding['severity']} | {finding['title']} | {location} | {finding['fix']} |")
    lines.extend(["", "_Generated by pi_scan.py — static analysis finds leads, not verdicts. Confirm each finding manually._"])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Static prompt-injection weakness scanner")
    parser.add_argument("target", help="System prompt or instruction file to scan")
    parser.add_argument("--json", dest="json_path", help="Write JSON report to this path")
    parser.add_argument("--md", dest="md_path", help="Write Markdown report to this path")
    args = parser.parse_args()

    try:
        with open(args.target, "r", encoding="utf-8", errors="replace") as file_handle:
            text = file_handle.read()
    except OSError as error:
        print(f"error: cannot read {args.target}: {error}", file=sys.stderr)
        sys.exit(2)
    if not text.strip():
        print("error: target file is empty", file=sys.stderr)
        sys.exit(2)

    findings = scan(text)
    score = risk_score(findings)
    print_report(args.target, findings, score)

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as file_handle:
            json.dump(to_json(args.target, findings, score), file_handle, indent=2, ensure_ascii=False)
        print(f"JSON report written to {args.json_path}")
    if args.md_path:
        with open(args.md_path, "w", encoding="utf-8") as file_handle:
            file_handle.write(to_markdown(args.target, findings, score))
        print(f"Markdown report written to {args.md_path}")

    sys.exit(1 if any(finding["severity"] in ("Critical", "High") for finding in findings) else 0)


if __name__ == "__main__":
    main()
