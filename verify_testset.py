#!/usr/bin/env python3
"""Independent end-to-end verification of the test-set scan.

Re-collects the corpus from the pinned commits, checks it against the
committed manifest (TESTSET_MANIFEST.md / manifest-test.jsonl), then
re-runs the registered frozen scanner (v2.3.2) and prints the aggregate.

Run anywhere with internet:  python3 verify_testset.py
"""
import hashlib
import io
import json
import math
import os
import re
import statistics
import sys
import urllib.request
import zipfile
from collections import Counter
from pathlib import Path

REPOS = [
    ("copilot",        "github/awesome-copilot",           "336af71f1b7d2e6e15a8a986ba79ca031a40549b"),
    ("subagents",      "wshobson/agents",                  "c4b82b0ad771190355eb8e204b1329732a18449a"),
    ("gpt-prompts",    "LouisShark/chatgpt_system_prompt", "37a95e8a062d78424546e5acfbe0f95b3de79e2a"),
    ("prompt-library", "0xeb/TheBigPromptLibrary",         "655667d2dd43bad65f189ec49d8606bf3e8d967e"),
]
REPO = "screem500/prompt-injection-auditor"
FROZEN_COMMIT = "b1b80fb724cf30694a7e174ae593cba16cdcb3a6"
SCANNER_SHA256 = "93dc6ef7e288806a7930fde5cc7962f9e58012c40ed6b6847adc762d8df8e377"
SCANNER_FILES = ["pi_scan.py", "language_rules.py", "normalization.py", "rule_docs.py"]
MIN_CHARS = 200

EXPECTED = {
    "files": 2491, "mean": 73.2, "median": 71, "severe": 1362, "hardened": 0,
    "sources": {"copilot": 824, "subagents": 183, "gpt-prompts": 1386, "prompt-library": 98},
}

BUILD = Path("verify_build")
PROMPT_DIR = re.compile(r"(?i)^(prompts?|system[-_]?prompts?|gpts?)/")
META_BASENAME = re.compile(
    r"(?i)^(readme|licen[cs]e|contributing|changelog|security|codeowners|"
    r"support|toc\.md|getting_started|agents\.md|claude\.md|gemini\.md)")


def eligible(relpath):
    parts = relpath.split("/")
    base = parts[-1].lower()
    if ".github" in parts or "docs" in parts:
        return False
    if META_BASENAME.match(base):
        return False
    if base == "skill.md":
        return True
    if re.search(r"\.(agent|instructions|prompt)\.md$", base):
        return True
    if base.endswith(".mdc"):
        return True
    if PROMPT_DIR.match(relpath) and base.endswith((".md", ".txt")):
        return True
    return False


def fetch(url, binary=False):
    import time
    last = None
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "verify-testset"})
            with urllib.request.urlopen(req, timeout=240) as r:
                data = r.read()
            return data if binary else data.decode("utf-8", errors="replace")
        except Exception as e:  # network hiccup — wait and retry
            last = e
            print(f"  (network retry {attempt + 1}/4: {type(e).__name__})")
            time.sleep(3 * (attempt + 1))
    raise last


print("== 1/4  re-collecting corpus from pinned commits ==")
corpus = BUILD / "corpus"
corpus.mkdir(parents=True, exist_ok=True)
rows = []
seen = set()
for sid, repo, sha in REPOS:
    zdata = fetch(f"https://codeload.github.com/{repo}/zip/{sha}", binary=True)
    kept = 0
    with zipfile.ZipFile(io.BytesIO(zdata)) as z:
        names = [n for n in z.namelist() if not n.endswith("/")]
        prefix = names[0].split("/")[0] + "/"
        for name in sorted(names):
            rel = name[len(prefix):]
            if not rel or not eligible(rel):
                continue
            text = (z.read(name).decode("utf-8", errors="replace")
                    .replace("\r\n", "\n").replace("\r", "\n"))
            if len(text) < MIN_CHARS:
                continue
            h = hashlib.sha256(text.encode("utf-8")).hexdigest()
            if h in seen:
                continue
            seen.add(h)
            ext = os.path.splitext(rel)[1] or ".txt"
            out = f"{sid}--{kept:04d}{ext}"
            (corpus / out).write_text(text, encoding="utf-8")
            rows.append({"file": out, "source": sid, "sha256": h})
            kept += 1
    print(f"  {sid:15s} kept={kept}")

print("\n== 2/4  comparing against the committed manifest ==")
committed = [json.loads(l) for l in
             fetch(f"https://raw.githubusercontent.com/{REPO}/main/manifest-test.jsonl").splitlines()]
ok_hashes = {r["sha256"] for r in rows} == {r["sha256"] for r in committed}
mine_counts = Counter(r["source"] for r in rows)
ok_counts = all(mine_counts[s] == n for s, n in EXPECTED["sources"].items())
print(f"  file-hash set identical to committed manifest: {ok_hashes}")
print(f"  per-source counts: {dict(mine_counts)} (expected {EXPECTED['sources']})")
if not (ok_hashes and ok_counts):
    sys.exit("MISMATCH: re-collected corpus differs from the sealed manifest. Stop here.")

print("\n== 3/4  fetching the frozen scanner (pinned commit) ==")
sdir = BUILD / "scanner"
sdir.mkdir(exist_ok=True)
local = Path.home() / "pia-work" / "scripts"
if (local / "pi_scan.py").exists() and \
   hashlib.sha256((local / "pi_scan.py").read_bytes()).hexdigest() == SCANNER_SHA256:
    for f in SCANNER_FILES:  # local clone already carries the frozen commit
        (sdir / f).write_bytes((local / f).read_bytes())
    print(f"  using local clone {local} (hash-verified)")
else:
    import base64 as b64mod
    for f in SCANNER_FILES:
        try:
            (sdir / f).write_text(
                fetch(f"https://raw.githubusercontent.com/{REPO}/{FROZEN_COMMIT}/scripts/{f}"),
                encoding="utf-8")
        except Exception:  # some networks 404 raw-at-SHA; the API path serves it
            meta = json.loads(fetch(
                f"https://api.github.com/repos/{REPO}/contents/scripts/{f}?ref={FROZEN_COMMIT}"))
            (sdir / f).write_bytes(b64mod.b64decode(meta["content"]))
actual = hashlib.sha256((sdir / "pi_scan.py").read_bytes()).hexdigest()
print(f"  pi_scan.py sha256 = {actual}")
if actual != SCANNER_SHA256:
    sys.exit("MISMATCH: scanner fingerprint != registered v2.3.2 fingerprint. Stop here.")
print("  fingerprint OK (registered v2.3.2)")

print("\n== 4/4  running the single frozen scan ==")
sys.path.insert(0, str(sdir.resolve()))
from pi_scan import risk_score, scan

scores = []
rule_hits = Counter()
by_source = {}
for p in sorted(corpus.iterdir()):
    findings = scan(p.read_text(encoding="utf-8", errors="replace"))
    score = risk_score(findings)
    scores.append(score)
    src = p.name.split("--")[0]
    by_source.setdefault(src, []).append(score)
    for f in findings:
        rule_hits[f["id"]] += 1

n = len(scores)
severe = sum(1 for s in scores if s >= 70)   # the scanner's own verdict bands:
high = sum(1 for s in scores if 40 <= s < 70)  # >=70 SEVERELY EXPOSED,
moderate = sum(1 for s in scores if 15 <= s < 40)  # 40-69 HIGH RISK,
hardened = sum(1 for s in scores if s < 15)  # 15-39 MODERATE, <15 HARDENED
mean = statistics.mean(scores)
median = statistics.median(scores)
print(f"\nfiles scanned: {n}")
print(f"RISK score: mean {mean:.1f} | median {median:.0f} | min {min(scores)} | max {max(scores)}")
print("verdict bands (the scanner's own):")
print(f"  SEVERELY EXPOSED (>=70): {severe} ({severe/n*100:.1f}%)")
print(f"  HIGH RISK (40-69):       {high} ({high/n*100:.1f}%)")
print(f"  MODERATE (15-39):        {moderate} ({moderate/n*100:.1f}%)")
print(f"  HARDENED (<15):          {hardened} ({hardened/n*100:.1f}%)")
print("\nby source (n / mean RISK / % severe):")
for s, vals in sorted(by_source.items()):
    sv = sum(1 for v in vals if v >= 70)
    print(f"  {s:<15} n={len(vals):4d}  mean {statistics.mean(vals):5.1f}  severe {sv/len(vals)*100:5.1f}%")

print("\n== verdict ==")
checks = [
    ("files == 2491", n == EXPECTED["files"]),
    ("mean == 73.2", round(mean, 1) == EXPECTED["mean"]),
    ("median == 71", median == EXPECTED["median"]),
    ("severe == 1362", severe == EXPECTED["severe"]),
    ("hardened == 0", hardened == EXPECTED["hardened"]),
]
for label, ok in checks:
    print(f"  [{'OK ' if ok else 'FAIL'}] {label}")
print("\nALL CHECKS PASSED — reproduction confirmed." if all(ok for _, ok in checks)
      else "\nMISMATCH — send this output before proceeding.")
