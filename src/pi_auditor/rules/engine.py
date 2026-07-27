"""Central regex rule engine used by all detection surfaces."""

from typing import Iterable, List, Optional, Sequence, Tuple
import re

from .models import PatternRule, RuleHit


def evaluate_rules(
    text: str,
    rules: Iterable[PatternRule],
    *,
    channel: Optional[str] = None,
    first_match_per_rule: bool = True,
) -> List[RuleHit]:
    """Evaluate rules against text and return normalized hits.

    A rule with no channels is global. Rules declaring channels are evaluated
    only when the requested channel is included.
    """

    hits: List[RuleHit] = []
    for rule in rules:
        if channel and rule.channels and channel not in rule.channels:
            continue
        rx = re.compile(rule.pattern, rule.flags)
        for match in rx.finditer(text):
            hits.append(
                RuleHit(
                    rule_id=rule.id,
                    label=rule.label,
                    weight=rule.weight,
                    start=match.start(),
                    end=match.end(),
                    matched_text=match.group(0),
                )
            )
            if first_match_per_rule:
                break
    return hits


def score_rules(
    text: str,
    rules: Sequence[PatternRule],
    *,
    channel: Optional[str] = None,
    cap: int = 100,
) -> Tuple[int, List[RuleHit]]:
    """Evaluate weighted rules and return capped score plus hits."""

    hits = evaluate_rules(text, rules, channel=channel)
    return min(cap, sum(hit.weight for hit in hits)), hits
