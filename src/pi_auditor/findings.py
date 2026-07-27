"""Canonical finding model shared by static and runtime detection surfaces."""

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEVERITY_DEFAULT_WEIGHT = {"Critical": 35, "High": 18, "Medium": 8, "Low": 3, "Info": 0}
CONFIDENCE_MULTIPLIER = {"Low": 0.75, "Medium": 0.9, "High": 1.0}


@dataclass(frozen=True)
class Location:
    """Source location for one finding."""

    line: Optional[int] = None
    column: Optional[int] = None
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    json_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            key: value
            for key, value in {
                "line": self.line,
                "column": self.column,
                "end_line": self.end_line,
                "end_column": self.end_column,
                "json_path": self.json_path,
            }.items()
            if value is not None
        }


@dataclass(frozen=True)
class Finding:
    """One normalized security finding emitted by any project component."""

    id: str
    title: str
    severity: str
    category: str = "generic"
    channel: str = "unknown"
    weight: int = 0
    confidence: str = "High"
    detail: str = ""
    remediation: str = ""
    evidence: str = ""
    locations: Tuple[Location, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def effective_weight(self) -> int:
        base = self.weight or SEVERITY_DEFAULT_WEIGHT.get(self.severity, 0)
        multiplier = CONFIDENCE_MULTIPLIER.get(self.confidence, 1.0)
        return max(0, int(round(base * multiplier)))

    @property
    def fingerprint(self) -> Tuple[Any, ...]:
        """Stable fingerprint used to suppress exact duplicate findings."""

        locations = tuple(
            (loc.line, loc.column, loc.end_line, loc.end_column, loc.json_path)
            for loc in self.locations
        )
        return self.id, self.channel, locations, self.evidence

    def legacy_text(self) -> str:
        """Render the compact format historically exposed by runtime guards."""

        weight = self.weight or self.effective_weight
        return f"{self.title} (+{weight})" if weight else self.title

    def to_dict(self, *, include_legacy: bool = True) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "channel": self.channel,
            "weight": self.weight or self.effective_weight,
            "confidence": self.confidence,
            "detail": self.detail,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "locations": [location.to_dict() for location in self.locations],
            "metadata": dict(self.metadata),
        }
        if include_legacy:
            data["lines"] = sorted({loc.line for loc in self.locations if loc.line is not None})
            data["fix"] = self.remediation
        return data

    def to_legacy_scanner_dict(self) -> Dict[str, Any]:
        """Return the exact field shape consumed by legacy scanner callers."""

        return {
            "id": self.id,
            "severity": self.severity,
            "title": self.title,
            "lines": sorted({loc.line for loc in self.locations if loc.line is not None}),
            "detail": self.detail,
            "fix": self.remediation,
        }

    @classmethod
    def from_legacy_scanner_dict(cls, data: Mapping[str, Any]) -> "Finding":
        lines = tuple(Location(line=int(line)) for line in data.get("lines", []) if line is not None)
        severity = str(data.get("severity", "Medium"))
        return cls(
            id=str(data.get("id", "PI-UNKNOWN")),
            title=str(data.get("title", data.get("id", "Unknown finding"))),
            severity=severity,
            category=str(data.get("category", "static_audit")),
            channel=str(data.get("channel", "system_prompt")),
            weight=int(data.get("weight", SEVERITY_DEFAULT_WEIGHT.get(severity, 0))),
            confidence=str(data.get("confidence", "High")),
            detail=str(data.get("detail", "")),
            remediation=str(data.get("remediation", data.get("fix", ""))),
            evidence=str(data.get("evidence", "")),
            locations=lines,
            metadata=dict(data.get("metadata", {})),
        )


def deduplicate_findings(findings: Iterable[Finding]) -> Tuple[Finding, ...]:
    """Remove exact duplicates while preserving first-seen order."""

    unique = []
    seen = set()
    for finding in findings:
        if finding.fingerprint in seen:
            continue
        seen.add(finding.fingerprint)
        unique.append(finding)
    return tuple(unique)
