"""Typed rule models shared by scanner and runtime guards."""

from dataclasses import dataclass, field
from typing import FrozenSet, Optional, Pattern, Tuple
import re


@dataclass(frozen=True)
class PatternRule:
    """One regex-backed detection rule usable across one or more channels."""

    id: str
    pattern: str
    label: str
    weight: int = 0
    severity: Optional[str] = None
    category: str = "generic"
    channels: FrozenSet[str] = field(default_factory=frozenset)
    flags: int = re.IGNORECASE

    def compile(self) -> Pattern[str]:
        return re.compile(self.pattern, self.flags)


@dataclass(frozen=True)
class RuleHit:
    """Normalized match emitted by the central rule engine."""

    rule_id: str
    label: str
    weight: int
    start: int
    end: int
    matched_text: str


@dataclass(frozen=True)
class RuleSet:
    """Named immutable group of rules for a detection channel."""

    name: str
    rules: Tuple[PatternRule, ...]
