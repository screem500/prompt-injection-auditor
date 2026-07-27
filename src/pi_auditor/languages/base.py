"""Language-pack contracts for multilingual prompt-injection analysis."""

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Tuple

Normalizer = Callable[[str], str]
Detector = Callable[[str], float]


@dataclass(frozen=True)
class LanguagePack:
    """Immutable bundle of language-specific normalization and rule assets."""

    code: str
    name: str
    version: str
    normalize: Normalizer
    detect: Detector
    attack_rules: Tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    defensive_context_patterns: Tuple[str, ...] = field(default_factory=tuple)
    capabilities: Mapping[str, Any] = field(default_factory=dict)

    def confidence(self, text: str) -> float:
        """Return a bounded 0.0-1.0 language-presence confidence."""
        return max(0.0, min(1.0, float(self.detect(text))))

    def supports(self, capability: str) -> bool:
        return capability in self.capabilities

    def get(self, capability: str, default=()):
        return self.capabilities.get(capability, default)
