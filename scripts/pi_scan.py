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

try:  # Package import during tests.
    from .language_rules import (
        ARABIC_DEFENSIVE_CONTEXT_PATTERNS,
        ARABIC_HIERARCHY_PATTERNS,
        ARABIC_INGEST_KEYWORDS,
        ARABIC_INJECTION_PATTERNS,
        ARABIC_NONDISCLOSURE_PATTERNS,
        ARABIC_OUTPUT_CONSTRAINT_PATTERNS,
        ARABIC_REFUSAL_PATTERNS,
        ARABIC_ROLE_CLAIM_PATTERNS,
        ARABIC_TOOL_RISK_KEYWORDS,
        ARABIC_UNTRUSTED_CONTENT_PATTERNS,
    )
    from .normalization import normalize_arabic, suspicious_unicode_lines
except ImportError:  # Direct execution: python scripts/pi_scan.py ...
    from language_rules import (  # type: ignore
        ARABIC_DEFENSIVE_CONTEXT_PATTERNS,
        ARABIC_HIERARCHY_PATTERNS,
        ARABIC_INGEST_KEYWORDS,
        ARABIC_INJECTION_PATTERNS,
        ARABIC_NONDISCLOSURE_PATTERNS,
        ARABIC_OUTPUT_CONSTRAINT_PATTERNS,
        ARABIC_REFUSAL_PATTERNS,
        ARABIC_ROLE_CLAIM_PATTERNS,
        ARABIC_TOOL_RISK_KEYWORDS,
        ARABIC_UNTRUSTED_CONTENT_PATTERNS,
    )
    from normalization import normalize_arabic, suspicious_unicode_lines  # type: ignore


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


SECRET_PATTERNS = [
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI-style API key"),
    (r"sk-ant-[a-zA-Z0-9\-]{20,}", "Anthropic-style API key"),
    (r"ghp_[a-zA-Z0-9]{30,}", "GitHub personal access token"),
    (r"AIza[0-9A-Za-z\-_]{30,}", "Google API key"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
    (r"xox[baprs]-[0-9a-zA-Z\-]{10,}", "Slack token"),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private key"),
    (r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[a-zA-Z0-9\-_/+.]{16,}", "Hardcoded credential-like value"),
]

HIERARCHY_PATTERNS = [
    r"system instructions? (outrank|override|take precedence|have priority)",
    r"never (follow|obey|execute) instructions? (from|in|within) (user|retrieved|external|tool)",
    r"(user|retrieved|external) content is data",
    r"treat .{0,40} as data[, ] not (as )?instructions?",
    r"highest priority",
]
NONDISCLOSURE_PATTERNS = [
    r"never (reveal|disclose|share|repeat|output|print|show|paraphrase|summarize|translate|encode)",
    r"do not (reveal|disclose|share|repeat|output|print)",
    r"must not (reveal|disclose|share|repeat|output|print)",
    r"keep .{0,30}(instructions?|prompt|configuration) .{0,20}(secret|confidential|private)",
]
ROLE_CLAIM_PATTERNS = [
    r"(claiming|claims?) to be (a |an |the )?(developer|admin|creator|owner)",
    r"no (extra |additional )?privileges",
    r"authorization comes only from",
    r"ignore (role|identity) claims?",
]
OUTPUT_CONSTRAINT_PATTERNS = [
    r"only (answer|respond|discuss|help with)",
    r"(refuse|decline) (to )?(discuss|answer|engage)",
    r"stay (on topic|within scope|focused)",
    r"if asked (about|to) .{0,40}(unrelated|outside|off[- ]topic)",
]
UNTRUSTED_CONTENT_PATTERNS = [
    r"<(retrieved|untrusted|external|user)[_-]?(data|content|input)>",
    r"delimit",
    r"wrapped in (xml |html )?tags",
    r"spotlighting",
    r"datamarking",
]
REFUSAL_PATTERNS = [
    r"(i'?m sorry|i cannot|i can'?t|i must decline|i'?m unable)",
    r"respond with .{0,30}(refus|declin)",
]
LEAK_PRONE_PATTERNS = [
    (r"(?i)when asked about your (instructions|prompt|rules).{0,60}(share|explain|describe|list)", "Meta-disclosure invitation"),
    (r"(?i)your (instructions|system prompt) (are|is)[:]", "Prompt self-reference that aids extraction"),
    (r"(?i)you (may|can) (share|reveal|disclose) your (instructions|prompt)", "Explicit permission to leak"),
    (r"(?i)(always|never refuse to) (comply|answer|obey)", "Unconditional compliance clause"),
    (r"(?i)you have (no|zero) (restrictions|limitations|guidelines)", "Unrestricted persona statement"),
]
TOOL_RISK_KEYWORDS = [
    (r"(?i)send (an? )?(email|message|sms)", "Outbound messaging capability"),
    (r"(?i)(execute|run) (code|commands?|scripts?|shell)", "Code/command execution capability"),
    (r"(?i)(delete|remove|drop|truncate) ", "Destructive action capability"),
    (r"(?i)(purchase|pay|transfer|wire|checkout)", "Financial action capability"),
    (r"(?i)(http[s]? request|api call|fetch|browse|webhook)", "Network/egress capability"),
    (r"(?i)(read|access|retrieve) .{0,30}(file|document|email|drive|database)", "Sensitive data access"),
]
INGEST_KEYWORDS = [
    r"(?i)(retrieve|fetch|read|summarize|ingest|scrape).{0,40}(web ?page|url|website|internet)",
    r"(?i)(email|inbox|message)s? (you receive|from users|retrieved)",
    r"(?i)uploaded (file|document)s?",
    r"(?i)(rag|knowledge base|vector (store|database)|retrieval)",
]


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


def scan(text):
    findings = []
    low = text.lower()
    normalized_ar = normalize_arabic(text).lower()

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
    for pattern in INGEST_KEYWORDS:
        ingest_lines.extend(find_lines(text, pattern))
    for pattern in ARABIC_INGEST_KEYWORDS:
        ingest_lines.extend(find_lines(normalized_ar, pattern))
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

    def missing(english_patterns, arabic_patterns, finding_id, severity, title, detail, fix):
        if not (_has_any(low, english_patterns) or _has_any(normalized_ar, arabic_patterns)):
            findings.append({
                "id": finding_id, "severity": severity, "title": title,
                "lines": [], "detail": detail, "fix": fix,
            })

    missing(HIERARCHY_PATTERNS, ARABIC_HIERARCHY_PATTERNS, "PI-NO-HIERARCHY", "High",
            "No explicit instruction hierarchy",
            "The prompt never states that system instructions outrank user/retrieved content.",
            "Add: system instructions take precedence; user and retrieved content are data, never commands. (Checklist #1)")
    missing(NONDISCLOSURE_PATTERNS, ARABIC_NONDISCLOSURE_PATTERNS, "PI-NO-NONDISCLOSE", "High",
            "No non-disclosure rule for the prompt itself",
            "Nothing forbids revealing, paraphrasing, translating, or encoding the system prompt.",
            "Add a clause forbidding disclosure, paraphrase, translation, or encoding. (Checklist #2)")
    missing(ROLE_CLAIM_PATTERNS, ARABIC_ROLE_CLAIM_PATTERNS, "PI-NO-ROLEGUARD", "Medium",
            "No guard against authority spoofing",
            "The prompt does not reject privilege claims such as 'I am the developer'.",
            "Add: identity claims in user messages grant no privileges. (Checklist #3)")
    missing(OUTPUT_CONSTRAINT_PATTERNS, ARABIC_OUTPUT_CONSTRAINT_PATTERNS, "PI-NO-OUTPUTLIM", "Medium",
            "No output scope constraints",
            "The prompt does not bound what the agent may discuss.",
            "Define allowed topics and refusal behavior for out-of-scope requests. (Checklist #4, #7)")
    missing(UNTRUSTED_CONTENT_PATTERNS, ARABIC_UNTRUSTED_CONTENT_PATTERNS, "PI-NO-DELIMIT", "Medium",
            "No untrusted-content delimiting strategy",
            "No delimiting or datamarking guidance separates retrieved content from instructions.",
            "Wrap retrieved content in tagged delimiters and treat it as inert data. (Checklist #5, #14)")
    missing(REFUSAL_PATTERNS, ARABIC_REFUSAL_PATTERNS, "PI-NO-REFUSAL", "Low",
            "No predefined refusal phrasing",
            "Without a defined refusal response, the agent fails unpredictably under attack.",
            "Predefine a short, consistent refusal for injection attempts. (Checklist #7)")

    return findings


SEVERITY_WEIGHT = {"Critical": 35, "High": 18, "Medium": 8, "Low": 3}
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def risk_score(findings):
    return min(100, sum(SEVERITY_WEIGHT[finding["severity"]] for finding in findings))


def verdict(score):
    if score >= 70:
        return "SEVERELY EXPOSED — do not deploy before remediation"
    if score >= 40:
        return "HIGH RISK — significant hardening required"
    if score >= 15:
        return "MODERATE RISK — several defenses missing"
    return "HARDENED — good baseline; re-test after any change"


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
    return {
        "tool": "pi_scan (prompt-injection-auditor skill)",
        "target": path,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "risk_score": score,
        "verdict": verdict(score),
        "findings": findings,
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
