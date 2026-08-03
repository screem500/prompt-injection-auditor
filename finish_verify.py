import hashlib, statistics, sys
from pathlib import Path

sdir = Path.home() / "pia-work" / "scripts"
actual = hashlib.sha256((sdir / "pi_scan.py").read_bytes()).hexdigest()
print("scanner sha256:", actual)
assert actual == "93dc6ef7e288806a7930fde5cc7962f9e58012c40ed6b6847adc762d8df8e377", "FINGERPRINT MISMATCH"
sys.path.insert(0, str(sdir))
from pi_scan import risk_score, scan

corpus = Path("verify_build/corpus")
scores, by_source = [], {}
for p in sorted(corpus.iterdir()):
    findings = scan(p.read_text(encoding="utf-8", errors="replace"))
    s = risk_score(findings)
    scores.append(s)
    by_source.setdefault(p.name.split("--")[0], []).append(s)

n = len(scores); hard = sum(1 for s in scores if s >= 90)
mean = statistics.mean(scores); median = statistics.median(scores)
print(f"files scanned: {n}")
print(f"mean {mean:.1f} | median {median:.0f} | min {min(scores)} | max {max(scores)}")
print(f"hardened (>=90): {hard} ({hard/n*100:.1f}%)")
for s, vals in sorted(by_source.items()):
    print(f"  {s:<15} n={len(vals):4d}  mean {statistics.mean(vals):5.1f}")
checks = [n == 2491, round(mean, 1) == 73.2, median == 71, hard == 499]
print()
print("ALL CHECKS PASSED - reproduction confirmed." if all(checks) else "MISMATCH - send this output.")
