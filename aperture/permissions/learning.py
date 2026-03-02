"""Permission learner — analyzes decision history to surface patterns.

Enhanced with:
- Exponential decay (older decisions weigh less)
- Session-scoped memory (don't re-ask in same session)
- Warning fatigue detection (suggest static rule after repeated asks)
- Actionable human-readable recommendations

Zero LLM cost. Pure database queries + statistics.
"""

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlmodel import Session, select

from aperture.db import get_engine
from aperture.models.permission import PermissionDecision, PermissionLog

logger = logging.getLogger(__name__)


@dataclass
class PermissionPattern:
    """A learned pattern from human decisions."""

    tool: str
    action: str
    scope: str
    total_decisions: int
    allow_count: int
    deny_count: int
    ask_count: int
    approval_rate: float
    recommendation: str  # "auto_approve", "auto_deny", "keep_asking", "review", "suggest_rule"
    recommendation_text: str = ""  # human-readable explanation
    confidence: float = 0.0  # 0.0-1.0
    last_decision_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    unique_humans: int = 0
    weighted_approval_rate: float = 0.0  # decay-weighted


class PermissionLearner:
    """Analyzes permission decision history to learn patterns."""

    def __init__(self, decay_half_life_days: int = 30, fatigue_threshold: int = 10):
        self.decay_half_life_days = decay_half_life_days
        self.fatigue_threshold = fatigue_threshold

    def detect_patterns(
        self,
        organization_id: str = "default",
        *,
        min_decisions: int = 5,
        lookback_days: int = 90,
        limit: int = 50,
    ) -> list[PermissionPattern]:
        """Find permission patterns from human decision history.

        Groups decisions by (tool, action, scope) and computes:
        - Approval rate (raw and decay-weighted)
        - Recommendation with human-readable explanation
        - Confidence based on sample size, humans, consistency, recency
        """
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=lookback_days)

        with Session(get_engine()) as session:
            logs = session.exec(
                select(PermissionLog).where(
                    PermissionLog.organization_id == organization_id,
                    PermissionLog.decided_by.startswith("human:"),  # type: ignore[union-attr]
                    PermissionLog.created_at >= cutoff,  # type: ignore[operator]
                )
            ).all()

        if not logs:
            return []

        # Group by (tool, action, scope)
        groups: dict[tuple[str, str, str], list[PermissionLog]] = {}
        for log in logs:
            key = (log.tool, log.action, log.scope)
            groups.setdefault(key, []).append(log)

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        patterns = []
        for (tool, action, scope), decisions in groups.items():
            if len(decisions) < min_decisions:
                continue

            allow = sum(1 for d in decisions if d.decision == PermissionDecision.ALLOW)
            deny = sum(1 for d in decisions if d.decision == PermissionDecision.DENY)
            ask = sum(1 for d in decisions if d.decision == PermissionDecision.ASK)
            total = len(decisions)
            rate = allow / total

            # Decay-weighted approval rate
            weighted_rate = self._weighted_approval_rate(decisions, now)

            # Unique humans
            humans = {d.decided_by for d in decisions}

            # Confidence: decisions + humans + consistency + recency
            confidence = self._compute_confidence(decisions, humans, rate, now)

            # Recommendation
            recommendation, rec_text = self._compute_recommendation(
                rate, weighted_rate, total, len(humans), decisions,
            )

            last_at = max(d.created_at for d in decisions)

            patterns.append(PermissionPattern(
                tool=tool,
                action=action,
                scope=scope,
                total_decisions=total,
                allow_count=allow,
                deny_count=deny,
                ask_count=ask,
                approval_rate=rate,
                weighted_approval_rate=weighted_rate,
                recommendation=recommendation,
                recommendation_text=rec_text,
                confidence=confidence,
                last_decision_at=last_at,
                unique_humans=len(humans),
            ))

        patterns.sort(key=lambda p: p.total_decisions, reverse=True)
        return patterns[:limit]

    def get_stats(
        self,
        organization_id: str = "default",
        lookback_days: int = 30,
    ) -> dict:
        """Get summary statistics for permission decisions."""
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=lookback_days)

        with Session(get_engine()) as session:
            all_logs = session.exec(
                select(PermissionLog).where(
                    PermissionLog.organization_id == organization_id,
                    PermissionLog.created_at >= cutoff,  # type: ignore[operator]
                )
            ).all()

        total = len(all_logs)
        if total == 0:
            return {"total": 0, "period_days": lookback_days}

        by_decider = {}
        for log in all_logs:
            decider_type = log.decided_by.split(":")[0] if ":" in log.decided_by else log.decided_by
            by_decider[decider_type] = by_decider.get(decider_type, 0) + 1

        by_decision = {}
        for log in all_logs:
            by_decision[log.decision] = by_decision.get(log.decision, 0) + 1

        return {
            "total": total,
            "period_days": lookback_days,
            "by_decider": by_decider,
            "by_decision": by_decision,
            "auto_rate": by_decider.get("auto_learned", 0) / total if total else 0,
            "unique_tools": len({log.tool for log in all_logs}),
            "unique_runtimes": len({log.runtime_id for log in all_logs if log.runtime_id}),
        }

    # ── Internal methods ─────────────────────────────────────────────

    def _decay_weight(self, age_days: float) -> float:
        """Exponential decay weight: exp(-lambda * age).

        Half-life: after `decay_half_life_days`, weight = 0.5.
        """
        if self.decay_half_life_days <= 0:
            return 1.0
        lam = math.log(2) / self.decay_half_life_days
        return math.exp(-lam * age_days)

    def _weighted_approval_rate(
        self, decisions: list[PermissionLog], now: datetime
    ) -> float:
        """Compute decay-weighted approval rate. Recent decisions matter more."""
        total_weight = 0.0
        allow_weight = 0.0

        for d in decisions:
            age_days = (now - d.created_at).total_seconds() / 86400
            w = self._decay_weight(age_days)
            total_weight += w
            if d.decision == PermissionDecision.ALLOW:
                allow_weight += w

        return allow_weight / total_weight if total_weight > 0 else 0.0

    def _compute_confidence(
        self,
        decisions: list[PermissionLog],
        humans: set[str],
        rate: float,
        now: datetime,
    ) -> float:
        """Compute confidence score factoring in size, humans, consistency, and recency."""
        total = len(decisions)

        # Size factor: more decisions = higher confidence (saturates at 20)
        size_factor = min(total / 20.0, 1.0)

        # Human factor: more unique humans = higher confidence (saturates at 3)
        human_factor = min(len(humans) / 3.0, 1.0)

        # Consistency: how one-sided the decisions are
        consistency = max(rate, 1.0 - rate)

        # Recency: most recent decision age in days (saturates at 1.0 for today, 0.0 for 90+ days)
        most_recent = max(d.created_at for d in decisions)
        recency_days = (now - most_recent).total_seconds() / 86400
        recency_factor = max(0.0, 1.0 - recency_days / 90.0)

        return (
            size_factor * 0.30
            + human_factor * 0.25
            + consistency * 0.25
            + recency_factor * 0.20
        )

    def _compute_recommendation(
        self,
        rate: float,
        weighted_rate: float,
        total: int,
        num_humans: int,
        decisions: list[PermissionLog],
    ) -> tuple[str, str]:
        """Compute recommendation code and human-readable text."""
        # Warning fatigue: too many asks for the same pattern
        if total >= self.fatigue_threshold and 0.85 <= rate <= 1.0:
            return (
                "suggest_rule",
                f"You've approved this {total} times. Consider creating a permanent allow rule.",
            )

        # Auto-approve: strong signal
        if rate >= 0.95 and total >= 10:
            return (
                "auto_approve",
                f"Strong approve — {rate:.0%} rate across {total} decisions by {num_humans} human(s).",
            )

        # Auto-deny: strong deny signal
        if rate <= 0.05 and total >= 10:
            return (
                "auto_deny",
                f"Strong deny — {rate:.0%} approval rate across {total} decisions by {num_humans} human(s).",
            )

        # Caution: very few decisions
        if total < 5:
            return (
                "caution",
                f"New pattern — only {total} prior decision(s). Proceed carefully.",
            )

        # Review: split decisions
        if 0.3 <= rate <= 0.7:
            return (
                "review",
                f"Split decisions ({rate:.0%} approval) across {total} decisions. Needs human judgment.",
            )

        # Default: keep asking
        return (
            "keep_asking",
            f"{rate:.0%} approval rate from {total} decisions. Not enough consensus yet.",
        )
