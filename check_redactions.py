#!/usr/bin/env python3
"""
check_redactions.py — Fail when a private artifact is about to be published.

The repository's own release rule: nothing personal, private, or live-looking
ships. This sweep is the automated half of that rule, referenced from the
pre-commit hook documented in check_rule_docs.py:

    #!/bin/sh
    python3 check_redactions.py || exit 1
    python3 check_rule_docs.py  || exit 1

Three checks over every tracked text file:

  1. Private filesystem paths — a literal /root/<name>, /home/<name>, or
     C:\\Users\\<name> ties the repo to one machine and one person.
  2. Personal email addresses — the project is contacted through GitHub;
     no personal mailbox belongs in the tree.
  3. Live-looking credentials — anything the scanner's own PI-SECRET engine
     would call Critical outside the documented fixture locations. Test
     files, the corpus generator and the attack-payload reference contain
     deliberate dummies; everywhere else a credential-shaped string is a
     leak candidate.

Allowlisting is per (file, check) with a written justification, so an
exception is a decision, not an accident. Exit code 1 on any finding.
"""

import os
import re
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))

SKIP_DIRS = {".git", "__pycache__", "corpus-hardened", "corpus-vulnerable",
             "verify_build"}
TEXT_EXT = {".py", ".md", ".yml", ".yaml", ".txt", ".json", ".jsonl",
            ".toml", ".cfg", ".ini", ".sh"}

# --- check 1: private paths -------------------------------------------------
PRIVATE_PATH_RE = re.compile(
    # Fifth review round: the Windows alternative previously required TWO
    # literal backslashes (the JSON-escaped form), so an ordinary single-
    # backslash path (C:\Users\name) sailed through the privacy gate. Now
    # one or two separators both match, and case is ignored (c:\users too).
    r"(?i)(/root/\S+|/home/[^/\s]+/|C:\\{1,2}Users\\{1,2}[^\\\s]+|~/pia-work\b|\bpia-work\b)"
)

# --- check 2: personal emails ----------------------------------------------
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
EMAIL_ALLOW = re.compile(
    r"(example\.(com|org|net)|@2x\.|sentry\.io|w3\.org|@users\.noreply\.github\.com)$"
)

# --- check 3: live-looking credentials --------------------------------------
# Reuse the scanner's own engine: a string the project itself would flag
# Critical cannot be called safe by a weaker checker here.
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, ROOT)
try:
    from scripts.pi_scan import (
        SECRET_PATTERNS, SECRET_PLACEHOLDER_PATTERN,
        SECRET_SELF_DESCRIBING_PATTERN,
    )
except ImportError:
    SECRET_PATTERNS = None

# Locations whose credential-shaped strings are deliberate fixtures. Each
# entry must say WHY it is exempt.
FIXTURE_PATHS = {
    "tests/": "unit-test fixtures are the detection targets themselves",
    "make_corpus.py": "generates the deliberately vulnerable benchmark corpus",
    "references/test-payloads.md": "documented attack demonstrations",
}

# (relative path, check name) pairs allowed with justification. An entry here
# is a reviewed decision, re-checked on every run.
ALLOWLIST = {
    ("verify_testset.py", "private-path"): (
        "Path.home()/'pia-work' is a local cache hint for the frozen scanner, "
        "hash-verified with a network fallback; it names a directory, not a person"
    ),
    ("tests/test_fp_regression.py", "private-path"): (
        "synthetic audit_fixture paths are the deliberate fixtures for the "
        "single-backslash Windows-path regression tests (fifth review round); "
        "they name no real machine or person"
    ),
    ("manifest-test.jsonl", "credential"): (
        "sealed study manifest (metadata only); 'sk-coordination-strategies' "
        "is a source path in the corpus, not a key"
    ),
    ("manifest-test.jsonl", "email"): (
        "'@levelsio.md' inside a GPT-store filename is a source-file label, "
        "not a mailbox"
    ),
}

# The checker never scans itself: its own patterns and doc examples would
# self-match. This file, too, is a reviewed decision.
SELF = os.path.basename(__file__)


def _iter_text_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            ext = os.path.splitext(name)[1].lower()
            if ext in TEXT_EXT or name == ".gitignore":
                yield os.path.join(dirpath, name)


def _allowed(rel, check):
    return (rel, check) in ALLOWLIST or (os.path.basename(rel), check) in ALLOWLIST


def main():
    problems = []

    for path in _iter_text_files():
        rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
        if os.path.basename(rel) == SELF:
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue

        # check 1 — private paths
        if not _allowed(rel, "private-path"):
            for m in PRIVATE_PATH_RE.finditer(text):
                line = text[:m.start()].count("\n") + 1
                problems.append(f"{rel}:{line} private path fragment {m.group(1)!r}")

        # check 2 — personal emails
        if not _allowed(rel, "email"):
            for m in EMAIL_RE.finditer(text):
                if EMAIL_ALLOW.search(m.group(0)):
                    continue
                line = text[:m.start()].count("\n") + 1
                problems.append(f"{rel}:{line} email address {m.group(0)!r}")

        # check 3 — live-looking credentials (scanner's own engine)
        if SECRET_PATTERNS and not _allowed(rel, "credential"):
            if any(rel.startswith(p) for p in FIXTURE_PATHS):
                continue
            for pattern, label in SECRET_PATTERNS:
                for m in re.finditer(pattern, text):
                    window = text[max(0, m.start() - 140): m.end() + 60]
                    if re.search(SECRET_PLACEHOLDER_PATTERN, window):
                        continue
                    if re.search(SECRET_SELF_DESCRIBING_PATTERN, window):
                        continue
                    line = text[:m.start()].count("\n") + 1
                    problems.append(
                        f"{rel}:{line} live-looking credential ({label}); "
                        "if it is a fixture, move it under tests/ or say so in ALLOWLIST"
                    )

    if problems:
        print("BLOCKED - redaction sweep found publishable artifacts:\n")
        for p in problems:
            print("  -", p)
        print("\nNothing personal, private, or live-looking ships.")
        return 1

    print("check_redactions: OK - no private paths, personal emails, or live-looking credentials")
    return 0


if __name__ == "__main__":
    sys.exit(main())
