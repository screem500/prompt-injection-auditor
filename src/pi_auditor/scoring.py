"""Unified scoring policies for static audits and runtime guards."""

from dataclasses import dataclass, field
from typing import Dict, Iterable, Mapping, Optional, Tuple

from .findings import Finding, SEVERITY_DEFAULT_WEIGHT, deduplicate_findings


@dataclass(frozen=True)
class ScorePolicy:
    name: str
    cap: int = 100
    severity_weights: Mapping[str, int] = field(default_factory=lambda: dict(SEVERITY_DEFAULT_WEIGHT))
    warn_at: int = 30
    block_at: int = 60
    confidence_adjustment: bool = False
    deduplicate: bool = True


@dataclass(frozen=True)
class ScoreSummary:
    score: int
    verdict: str
    decision: Optional[str]
    counts: Mapping[str, int]
    finding_count: int
    effective_finding_count: int
    policy: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "score": self.score,
            "verdict": self.verdict,
            "decision": self.decision,
            "counts": dict(self.counts),
            "finding_count": self.finding_count,
            "effective_finding_count": self.effective_finding_count,
            "policy": self.policy,
        }


STATIC_AUDIT_POLICY = ScorePolicy(
    name="static-audit-v1-compatible",
    warn_at=15,
    block_at=40,
    confidence_adjustment=False,
)

RUNTIME_POLICY = ScorePolicy(
    name="runtime-v1-compatible",
    warn_at=30,
    block_at=60,
    confidence_adjustment=False,
)


def static_verdict(score: int) -> str:
    if score >= 70:
        return "SEVERELY EXPOSED — do not deploy before remediation"
    if score >= 40:
        return "HIGH RISK — significant hardening required"
    if score >= 15:
        return "MODERATE RISK — several defenses missing"
    return "HARDENED — good baseline; re-test after any change"


def runtime_decision(score: int, warn_at: int, block_at: int) -> str:
    if score >= block_at:
        return "BLOCK"
    if score >= warn_at:
        return "WARN"
    return "ALLOW"


def calculate_score(
    findings: Iterable[Finding],
    policy: ScorePolicy,
    *,
    warn_at: Optional[int] = None,
    block_at: Optional[int] = None,
    mode: str = "sum",
) -> ScoreSummary:
    """Calculate one normalized score summary.

    ``sum`` preserves the historical behavior. ``max`` is useful for JSON/tool
    chunks where the highest-risk independent chunk determines the decision.
    """

    original = tuple(findings)
    effective = deduplicate_findings(original) if policy.deduplicate else original
    weights = []
    for finding in effective:
        if finding.weight:
            value = finding.effective_weight if policy.confidence_adjustment else finding.weight
        else:
            base = policy.severity_weights.get(finding.severity, 0)
            value = finding.effective_weight if policy.confidence_adjustment else base
        weights.append(value)

    raw_score = max(weights, default=0) if mode == "max" else sum(weights)
    score = min(policy.cap, max(0, raw_score))
    counts: Dict[str, int] = {}
    for finding in effective:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    runtime = policy.name.startswith("runtime")
    resolved_warn = policy.warn_at if warn_at is None else warn_at
    resolved_block = policy.block_at if block_at is None else block_at
    decision = runtime_decision(score, resolved_warn, resolved_block) if runtime else None
    verdict = decision if runtime else static_verdict(score)
    return ScoreSummary(
        score=score,
        verdict=verdict,
        decision=decision,
        counts=counts,
        finding_count=len(original),
        effective_finding_count=len(effective),
        policy=policy.name,
    )
