#!/usr/bin/env python3
"""
check_rule_docs.py — Fail when a scanner rule is not documented where it should be.

The repository states its own rule in references/rule-inventory.md:
"an undocumented rule is a broken promise". This enforces it.

Four checks:

  1. Every rule ID in scripts/pi_scan.py appears in references/rule-inventory.md,
     which describes itself as the complete index.
  2. Every 2026 agent-runtime rule additionally appears in SKILL.md (the severity
     guide names them explicitly) and in references/attack-patterns-2026.md.
     Prompt-level rules are deliberately not required in SKILL.md: that file
     describes weakness classes in prose, not by ID.
  3. Every checklist number referenced from the code (Checklist #NN) exists as a
     numbered item in references/defense-checklist.md.
  4. Every stated rule count matches the real number of rule IDs.

Run manually:
    python3 check_rule_docs.py

Install alongside the redaction hook, in .git/hooks/pre-commit:
    #!/bin/sh
    python3 check_redactions.py || exit 1
    python3 check_rule_docs.py  || exit 1

Exit code 1 on any gap.
"""

import os
import re
import sys

CODE = "scripts/pi_scan.py"
INVENTORY = "references/rule-inventory.md"
CHECKLIST = "references/defense-checklist.md"

# 2026 agent-runtime family: these must also be named in SKILL.md and in the
# attack-pattern reference.
RUNTIME_RULES = {
    "PI-MCP",
    "PI-SANDBOX-BYPASS",
    "PI-MEMORY",
    "PI-SUPPLY-CHAIN",
    "PI-AUTOLOAD-CONFIG",
}
RUNTIME_DOCS = ["SKILL.md", "references/attack-patterns-2026.md"]

COUNT_FILES = ["README.md", "SKILL.md", INVENTORY]
COUNT_RE = re.compile(
    r"(\d+)\s+(?:scanner\s+)?rule IDs"
    r"|rule IDs:\s*(\d+)"
    r"|checks\s+(\d+)\s+rule IDs"
    r"|(\d+)\s+rules,"
)

# IDs that live in the docs on purpose and are not emitted by the scanner
DOC_ONLY = {"PI-EMBEDDED-INSTRUCTION"}


def read(path):
    if not os.path.isfile(path):
        return None
    return open(path, encoding="utf-8").read()


def main():
    src = read(CODE)
    if src is None:
        sys.exit(f"error: {CODE} not found - run this from the repository root")

    # Rule IDs are written two ways in this scanner: as a dict field
    # ("id": "PI-X") and as a positional argument to missing(...). Match any
    # quoted PI-* literal, which covers both.
    rule_ids = sorted(
        set(re.findall(r'["\'](PI-[A-Z0-9-]+)["\']', src)) - DOC_ONLY
    )
    if not rule_ids:
        sys.exit("error: no rule IDs found in the scanner - check the pattern")

    problems = []

    inventory = read(INVENTORY)
    if inventory is None:
        problems.append(f"{INVENTORY} is missing")
        inventory = ""

    for rid in rule_ids:
        if rid not in inventory:
            problems.append(f"{rid} is not in {INVENTORY}")
        if rid in RUNTIME_RULES:
            for doc in RUNTIME_DOCS:
                text = read(doc)
                if text is None:
                    problems.append(f"{doc} is missing")
                elif rid not in text:
                    problems.append(f"{rid} is not documented in {doc}")

    # every checklist reference from the code must exist
    checklist = read(CHECKLIST)
    if checklist is None:
        problems.append(f"{CHECKLIST} is missing")
    else:
        defined = set(re.findall(r"^(\d+)\.\s", checklist, re.M))
        referenced = set(re.findall(r"Checklist\s+#(\d+)", src))
        for n in sorted(referenced, key=int):
            if n not in defined:
                problems.append(
                    f"code references Checklist #{n}, not defined in {CHECKLIST}")

    # stated counts
    actual = len(rule_ids)
    for doc in COUNT_FILES:
        text = read(doc)
        if text is None:
            continue
        for m in COUNT_RE.finditer(text):
            stated = next(g for g in m.groups() if g)
            if int(stated) != actual:
                line = text[:m.start()].count("\n") + 1
                problems.append(
                    f"{doc}:{line} states {stated} rules, scanner has {actual}")

    print(f"scanner rule IDs ({actual}):")
    for rid in rule_ids:
        tag = "  [runtime]" if rid in RUNTIME_RULES else ""
        print(f"  {rid}{tag}")
    print()

    if problems:
        print("BLOCKED - rule documentation is incomplete:\n")
        for p in problems:
            print("  -", p)
        print("\nAn undocumented rule is a broken promise.")
        return 1

    print("check_rule_docs: OK - every rule is documented where it should be")
    return 0


if __name__ == "__main__":
    sys.exit(main())
