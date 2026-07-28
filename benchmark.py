#!/usr/bin/env python3
"""
benchmark.py — Run pi_scan across a corpus and summarise the results.

Turns "the scanner works" into a table someone else can check.

Usage:
    python3 benchmark.py corpus/                     # coloured terminal summary
    python3 benchmark.py corpus/ --md results.md     # markdown report
    python3 benchmark.py corpus/ --csv results.csv   # per-file rows
    python3 benchmark.py hardened/ --expect-clean    # false-positive run
    python3 benchmark.py corpus/ --no-color          # plain text

Colour is on when stdout is a terminal and NO_COLOR is unset. Use --force-color
to keep it when piping into a file or a screenshot tool.

What it reports:
    - score distribution and verdict counts
    - hit rate for every rule, so dead rules and noisy rules are both visible
    - files with no findings at all
    - with --expect-clean, any finding is a suspected false positive

Zero dependencies beyond the scanner itself. Python 3.8+.
"""

import argparse
import csv
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from scripts.pi_scan import scan, risk_score, verdict
except ImportError:
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                        "scripts"))
        from pi_scan import scan, risk_score, verdict
    except ImportError:
        sys.exit("error: could not import pi_scan - run this from the repository root")

TEXT_EXT = {".txt", ".md", ".yaml", ".yml", ".json"}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]

# Surface rules report a capability, not a defect. An agent that reads email
# is supposed to read email; the finding says "this is an attack surface,
# harden around it", not "this prompt is wrong". --expect-clean therefore
# ignores them, so the false-positive number measures defect rules only.
SURFACE_RULES = {"PI-INGEST", "PI-TOOLS"}

# --------------------------------------------------------------------------
# colour
# --------------------------------------------------------------------------

USE_COLOR = True

C = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "bred": "\033[91m",
    "orange": "\033[38;5;208m",
    "yellow": "\033[33m",
    "green": "\033[32m",
    "bgreen": "\033[92m",
    "cyan": "\033[36m",
    "blue": "\033[94m",
    "grey": "\033[90m",
}

SEV_COLOR = {
    "Critical": "bred",
    "High": "orange",
    "Medium": "yellow",
    "Low": "grey",
}


def c(text, *styles):
    if not USE_COLOR:
        return str(text)
    prefix = "".join(C[s] for s in styles if s in C)
    return f"{prefix}{text}{C['reset']}"


def score_color(score):
    if score >= 70:
        return "bred"
    if score >= 40:
        return "orange"
    if score > 0:
        return "yellow"
    return "bgreen"


def verdict_color(v):
    up = v.upper()
    if "SEVERELY" in up:
        return "bred"
    if "EXPOSED" in up:
        return "orange"
    if "HARDENED" in up:
        return "bgreen"
    return "yellow"


def rate_color(pct):
    # a rule that fires almost everywhere is probably noise;
    # a rule that never fires may be dead.
    if pct >= 90:
        return "bred"
    if pct >= 60:
        return "orange"
    if pct > 0:
        return "cyan"
    return "grey"


def header(text):
    line = "\u2500" * max(12, len(text) + 2)
    return f"{c(line, 'grey')}\n{c(text, 'bold', 'cyan')}\n{c(line, 'grey')}"


# --------------------------------------------------------------------------

def collect(root):
    if os.path.isfile(root):
        return [root]
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for name in sorted(filenames):
            if os.path.splitext(name)[1].lower() in TEXT_EXT:
                out.append(os.path.join(dirpath, name))
    return sorted(out)


def analyse(path):
    try:
        text = open(path, encoding="utf-8", errors="ignore").read()
    except OSError as exc:
        return None, f"unreadable: {exc}"
    findings = scan(text)
    score = risk_score(findings)
    return {
        "path": path,
        "score": score,
        "verdict": verdict(score),
        "findings": findings,
        "severities": Counter(f["severity"] for f in findings),
        "ids": [f["id"] for f in findings],
    }, None


def sev_badges(counts):
    parts = []
    for s in SEVERITY_ORDER:
        if counts[s]:
            parts.append(c(f"{s[0]}{counts[s]}", SEV_COLOR[s], "bold"))
    return " ".join(parts)


def main():
    global USE_COLOR

    ap = argparse.ArgumentParser(
        description="Run pi_scan across a corpus and summarise the results.")
    ap.add_argument("corpus", help="file or directory of prompt files")
    ap.add_argument("--md", help="write a markdown report to this path")
    ap.add_argument("--csv", help="write per-file rows to this path")
    ap.add_argument("--expect-clean", action="store_true",
                    help="treat any finding as a suspected false positive")
    ap.add_argument("--quiet", action="store_true",
                    help="summary only, no per-file lines")
    ap.add_argument("--strict", action="store_true",
                    help="count surface rules (PI-INGEST, PI-TOOLS) as failures too")
    ap.add_argument("--no-color", action="store_true", help="disable colour")
    ap.add_argument("--force-color", action="store_true",
                    help="keep colour even when not writing to a terminal")
    args = ap.parse_args()

    USE_COLOR = not args.no_color and (
        args.force_color
        or (sys.stdout.isatty() and os.environ.get("NO_COLOR") is None)
    )

    paths = collect(args.corpus)
    if not paths:
        sys.exit(f"error: no readable prompt files under {args.corpus}")

    results, errors = [], []
    for p in paths:
        r, err = analyse(p)
        if err:
            errors.append((p, err))
        else:
            results.append(r)

    if not results:
        sys.exit("error: nothing could be analysed")

    n = len(results)
    scores = sorted(r["score"] for r in results)
    rule_hits = Counter()
    for r in results:
        rule_hits.update(set(r["ids"]))
    sev_totals = Counter()
    for r in results:
        sev_totals.update(r["severities"])
    verdicts = Counter(r["verdict"] for r in results)
    clean = [r for r in results if not r["findings"]]

    print()
    print(c("  PROMPT INJECTION AUDITOR  ", "bold", "cyan"),
          c(f" benchmark: {args.corpus} ", "grey"))
    print()

    if not args.quiet:
        print(header(f"PER FILE  ({n})"))
        for r in sorted(results, key=lambda x: -x["score"]):
            sc = c(f"{r['score']:3}", score_color(r["score"]), "bold")
            badges = sev_badges(r["severities"]) or c("clean", "bgreen")
            pad = 26 - _visible(badges)
            print(f"  {sc}  {badges}{' ' * max(1, pad)}{c(r['path'], 'grey')}")
        print()

    print(header("SUMMARY"))
    print(f"  files analysed        {c(n, 'bold')}")
    print(f"  score  min/med/max    "
          f"{c(scores[0], score_color(scores[0]))} / "
          f"{c(scores[n // 2], score_color(scores[n // 2]))} / "
          f"{c(scores[-1], score_color(scores[-1]))}")
    mean = sum(scores) / n
    print(f"  mean score            {c(f'{mean:.1f}', score_color(mean))}")
    print(f"  files with 0 findings {c(len(clean), 'bgreen' if clean else 'grey')}")
    print()

    print(header("VERDICTS"))
    for v, cnt in verdicts.most_common():
        print(f"  {c(f'{cnt:4}', 'bold')}  {c(v, verdict_color(v))}")
    print()

    print(header("SEVERITY TOTALS"))
    for s in SEVERITY_ORDER:
        if sev_totals[s]:
            print(f"  {c(f'{sev_totals[s]:4}', SEV_COLOR[s], 'bold')}  "
                  f"{c(s, SEV_COLOR[s])}")
    print()

    print(header("RULE HIT RATE"))
    print(c("  files where the rule fired at least once", "grey"))
    print()
    for rid, cnt in rule_hits.most_common():
        pct = 100.0 * cnt / n
        col = rate_color(pct)
        bar = "\u2588" * int(pct / 4)
        print(f"  {c(f'{cnt:4}', 'bold')}  {c(f'{pct:5.1f}%', col)}  "
              f"{c(bar, col)}{' ' * (25 - int(pct / 4))} {c(rid, col)}")
    print()

    if errors:
        print(header(f"UNREADABLE  ({len(errors)})"))
        for p, e in errors:
            print(f"  {c(p, 'grey')}: {e}")
        print()

    exit_code = 0
    if args.expect_clean:
        for r in results:
            r["defects"] = [f for f in r["findings"]
                            if f["id"] not in SURFACE_RULES or args.strict]
        surfaced = sum(1 for r in results
                       if any(f["id"] in SURFACE_RULES for f in r["findings"]))
        dirty = [r for r in results if r["defects"]]
        if dirty:
            print(header("SUSPECTED FALSE POSITIVES"))
            print(f"  {c(f'{len(dirty)} of {n} hardened files produced defect findings', 'bred', 'bold')}")
            print()
            for r in dirty:
                print(f"  {c(r['path'], 'bold')}")
                for f in r["defects"]:
                    print(f"      {c('[' + f['severity'] + ']', SEV_COLOR[f['severity']])} "
                          f"{c(f['id'], 'bold')}: {f['title']}")
            print()
            exit_code = 1
        else:
            print(header("FALSE POSITIVE CHECK"))
            print(f"  {c(f'clean - no defect findings across {n} hardened files', 'bgreen', 'bold')}")
            if surfaced:
                print(f"  {c(f'{surfaced} file(s) reported a surface rule '
                             f'({", ".join(sorted(SURFACE_RULES))}) - expected, not counted',
                             'grey')}")
            print()

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["path", "score", "verdict", "critical", "high",
                        "medium", "low", "rule_ids"])
            for r in sorted(results, key=lambda x: -x["score"]):
                w.writerow([
                    r["path"], r["score"], r["verdict"],
                    r["severities"]["Critical"], r["severities"]["High"],
                    r["severities"]["Medium"], r["severities"]["Low"],
                    " ".join(sorted(set(r["ids"]))),
                ])
        print(f"  wrote {c(args.csv, 'cyan')}")

    if args.md:
        lines = []
        lines.append("# Benchmark results\n")
        lines.append(f"Corpus: `{args.corpus}` - {n} files\n")
        lines.append(f"Score min/median/max: {scores[0]} / "
                     f"{scores[n // 2]} / {scores[-1]}. Mean {mean:.1f}.\n")
        lines.append(f"Files with no findings: {len(clean)} of {n}.\n")
        lines.append("## Rule hit rate\n")
        lines.append("| Rule | Files | Rate |")
        lines.append("|------|-------|------|")
        for rid, cnt in rule_hits.most_common():
            lines.append(f"| `{rid}` | {cnt} | {100.0 * cnt / n:.1f}% |")
        lines.append("\n## Per file\n")
        lines.append("| Score | Verdict | Critical | High | Medium | Low | File |")
        lines.append("|-------|---------|----------|------|--------|-----|------|")
        for r in sorted(results, key=lambda x: -x["score"]):
            s = r["severities"]
            lines.append(
                f"| {r['score']} | {r['verdict']} | {s['Critical']} | "
                f"{s['High']} | {s['Medium']} | {s['Low']} | `{r['path']}` |")
        lines.append("")
        open(args.md, "w", encoding="utf-8").write("\n".join(lines))
        print(f"  wrote {c(args.md, 'cyan')}")

    if args.csv or args.md:
        print()

    return exit_code


def _visible(s):
    """Length of a string ignoring ANSI escape sequences."""
    out, i = 0, 0
    while i < len(s):
        if s[i] == "\033":
            while i < len(s) and s[i] != "m":
                i += 1
            i += 1
        else:
            out += 1
            i += 1
    return out


if __name__ == "__main__":
    sys.exit(main())
