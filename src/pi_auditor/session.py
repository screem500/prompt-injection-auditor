"""Stateful multi-turn prompt-injection detection.

The stateless shields remain the enforcement boundary for one message.  This
module adds a bounded per-session risk state that correlates weak or fragmented
signals across multiple user turns without granting old content indefinite
influence.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .findings import Finding, Location, deduplicate_findings
from .scoring import runtime_decision
from .shield import ALLOW, BLOCK, WARN, ShieldResult, shield_input


@dataclass(frozen=True)
class SessionPolicy:
    """Controls retention, decay, and escalation for one conversation."""

    warn_at: int = 30
    block_at: int = 60
    max_turns: int = 12
    ttl_seconds: int = 1800
    turn_decay: float = 0.82
    max_transcript_chars: int = 20_000
    fragment_bonus: int = 35
    repeated_probe_bonus: int = 12
    repeat_window: int = 5

    def __post_init__(self) -> None:
        if not 0 < self.turn_decay <= 1:
            raise ValueError("turn_decay must be in (0, 1]")
        if self.max_turns < 2:
            raise ValueError("max_turns must be at least 2")
        if self.ttl_seconds < 1:
            raise ValueError("ttl_seconds must be positive")
        if self.warn_at < 0 or self.block_at <= self.warn_at:
            raise ValueError("thresholds must satisfy 0 <= warn_at < block_at")


@dataclass(frozen=True)
class SessionTurn:
    index: int
    text: str
    timestamp: float
    score: int
    decision: str
    findings: Tuple[Finding, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "text": self.text,
            "timestamp": self.timestamp,
            "score": self.score,
            "decision": self.decision,
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(frozen=True)
class SessionResult:
    session_id: str
    decision: str
    score: int
    current: ShieldResult
    findings: Tuple[Finding, ...]
    active_turns: int
    total_turns: int
    notes: Tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "decision": self.decision,
            "score": self.score,
            "active_turns": self.active_turns,
            "total_turns": self.total_turns,
            "notes": list(self.notes),
            "current": {
                "decision": self.current.decision,
                "score": self.current.score,
                "findings": [f.to_dict() for f in self.current.structured_findings],
                "sanitized": self.current.sanitized,
            },
            "findings": [finding.to_dict() for finding in self.findings],
        }


class SessionRiskState:
    """Bounded state machine for multi-turn prompt-injection signals.

    Create one instance per user conversation.  Do not share an instance across
    users.  ``observe`` evaluates the current message, expires old turns,
    correlates the active transcript, and returns the effective session verdict.
    """

    def __init__(
        self,
        session_id: str,
        policy: Optional[SessionPolicy] = None,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not session_id:
            raise ValueError("session_id is required")
        self.session_id = session_id
        self.policy = policy or SessionPolicy()
        self._clock = clock
        self._turns: List[SessionTurn] = []
        self._total_turns = 0

    @property
    def turns(self) -> Tuple[SessionTurn, ...]:
        return tuple(self._turns)

    @property
    def total_turns(self) -> int:
        return self._total_turns

    def reset(self) -> None:
        self._turns.clear()
        self._total_turns = 0

    def _expire(self, now: float) -> None:
        cutoff = now - self.policy.ttl_seconds
        self._turns = [turn for turn in self._turns if turn.timestamp >= cutoff]
        if len(self._turns) > self.policy.max_turns:
            self._turns = self._turns[-self.policy.max_turns :]

    def _active_transcript(self) -> str:
        parts: List[str] = []
        total = 0
        for turn in reversed(self._turns):
            remaining = self.policy.max_transcript_chars - total
            if remaining <= 0:
                break
            value = turn.text[-remaining:]
            parts.append(value)
            total += len(value) + 1
        return "\n".join(reversed(parts))

    def _decayed_turn_score(self) -> int:
        score = 0.0
        newest = len(self._turns) - 1
        for position, turn in enumerate(self._turns):
            age = newest - position
            # Only retain a bounded contribution from any one historical turn;
            # an old direct block must not poison the session forever.
            contribution = min(turn.score, self.policy.block_at)
            score += contribution * (self.policy.turn_decay ** age)
        return min(100, int(round(score)))

    @staticmethod
    def _finding_categories(turn: SessionTurn) -> Tuple[str, ...]:
        return tuple(f.category for f in turn.findings)

    def _correlation_findings(self, transcript_result: ShieldResult) -> List[Finding]:
        findings: List[Finding] = []
        if len(self._turns) < 2:
            return findings

        individual_max = max((turn.score for turn in self._turns), default=0)
        # A joined transcript finding absent from every individual message is a
        # strong fragmented-instruction signal.
        individual_ids = {finding.id for turn in self._turns for finding in turn.findings}
        cross_turn = [
            finding for finding in transcript_result.structured_findings
            if finding.id not in individual_ids
        ]
        if cross_turn and transcript_result.score >= self.policy.warn_at:
            evidence = " | ".join(turn.text for turn in self._turns[-4:])
            findings.append(Finding(
                id="PI-MULTITURN-FRAGMENT",
                title="Instruction payload reconstructed across multiple turns",
                severity="High",
                category="multi_turn_injection",
                channel="session",
                weight=max(self.policy.fragment_bonus, transcript_result.score),
                confidence="High",
                detail=(
                    "The active transcript matches an injection pattern that was not present "
                    "in any individual message."
                ),
                remediation=(
                    "Block the session, reset conversational state, and require a fresh user "
                    "confirmation before enabling privileged tools."
                ),
                evidence=evidence[:1000],
                locations=(Location(),),
                metadata={"turns": [turn.index for turn in self._turns[-4:]]},
            ))

        # Repeated low/medium probes are meaningful even when no exact phrase is
        # reconstructed. Count distinct suspicious turns, not duplicate rules.
        recent = self._turns[-self.policy.repeat_window :]
        suspicious = [turn for turn in recent if turn.score >= 20 or turn.findings]
        if len(suspicious) >= 3 and individual_max < self.policy.block_at:
            findings.append(Finding(
                id="PI-MULTITURN-REPEATED-PROBING",
                title="Repeated prompt-injection probing across the session",
                severity="Medium",
                category="multi_turn_probing",
                channel="session",
                weight=self.policy.repeated_probe_bonus,
                confidence="Medium",
                detail="Several recent turns contain injection or extraction indicators.",
                remediation="Rate-limit the session, log the sequence, and require re-authentication for sensitive actions.",
                evidence=" | ".join(turn.text for turn in suspicious)[-1000:],
                metadata={"turns": [turn.index for turn in suspicious]},
            ))
        return findings

    def observe(self, user_text: str, *, timestamp: Optional[float] = None) -> SessionResult:
        if not isinstance(user_text, str):
            raise TypeError("user_text must be a string")
        now = self._clock() if timestamp is None else float(timestamp)
        self._expire(now)

        current = shield_input(
            user_text,
            warn_at=self.policy.warn_at,
            block_at=self.policy.block_at,
        )
        self._total_turns += 1
        self._turns.append(SessionTurn(
            index=self._total_turns,
            text=user_text,
            timestamp=now,
            score=current.score,
            decision=current.decision,
            findings=tuple(current.structured_findings),
        ))
        self._expire(now)

        transcript = self._active_transcript()
        transcript_result = shield_input(
            transcript,
            warn_at=self.policy.warn_at,
            block_at=self.policy.block_at,
        )
        correlated = self._correlation_findings(transcript_result)
        all_findings = list(f for turn in self._turns for f in turn.findings)
        all_findings.extend(correlated)
        effective_findings = deduplicate_findings(all_findings)

        base_score = max(current.score, self._decayed_turn_score())
        correlation_score = sum(f.weight for f in correlated)
        session_score = min(100, base_score + correlation_score)
        decision = runtime_decision(session_score, self.policy.warn_at, self.policy.block_at)
        notes: List[str] = []
        if correlated:
            notes.append("session-level correlation changed the effective risk")
        if decision != current.decision:
            notes.append(f"current message was {current.decision}; session decision escalated to {decision}")

        return SessionResult(
            session_id=self.session_id,
            decision=decision,
            score=session_score,
            current=current,
            findings=effective_findings,
            active_turns=len(self._turns),
            total_turns=self._total_turns,
            notes=tuple(notes),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": "1.0",
            "session_id": self.session_id,
            "total_turns": self._total_turns,
            "policy": {
                "warn_at": self.policy.warn_at,
                "block_at": self.policy.block_at,
                "max_turns": self.policy.max_turns,
                "ttl_seconds": self.policy.ttl_seconds,
                "turn_decay": self.policy.turn_decay,
                "max_transcript_chars": self.policy.max_transcript_chars,
                "fragment_bonus": self.policy.fragment_bonus,
                "repeated_probe_bonus": self.policy.repeated_probe_bonus,
                "repeat_window": self.policy.repeat_window,
            },
            "turns": [turn.to_dict() for turn in self._turns],
        }

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        *,
        clock: Callable[[], float] = time.time,
    ) -> "SessionRiskState":
        policy = SessionPolicy(**dict(data.get("policy", {})))
        state = cls(str(data["session_id"]), policy, clock=clock)
        state._total_turns = int(data.get("total_turns", 0))
        # Re-evaluate stored text instead of trusting serialized findings/scores.
        for item in data.get("turns", []):
            text = str(item.get("text", ""))
            result = shield_input(text, warn_at=policy.warn_at, block_at=policy.block_at)
            state._turns.append(SessionTurn(
                index=int(item.get("index", len(state._turns) + 1)),
                text=text,
                timestamp=float(item.get("timestamp", 0.0)),
                score=result.score,
                decision=result.decision,
                findings=tuple(result.structured_findings),
            ))
        return state
