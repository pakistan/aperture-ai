"""Crowd signal — aggregates org decision history into actionable signals.

Answers: "What did other people in my org decide about this?"
Also computes trends and auto-approve distance.
"""

import fnmatch
import logging
from datetime import datetime, timedelta, timezone

from sqlmodel import Session, select

from aperture.db import get_engine
from aperture.models.permission import PermissionDecision, PermissionLog
from aperture.models.verdict import OrgSignal

logger = logging.getLogger(__name__)


def get_org_signal(
    tool: str,
    action: str,
    scope: str,
    organization_id: str = "default",
    lookback_days: int = 90,
) -> OrgSignal | None:
    """Get crowd signal from this organization's decision history.

    Returns None if there is zero decision history for this pattern.
    """
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=lookback_days)

    with Session(get_engine()) as session:
        logs = session.exec(
            select(PermissionLog).where(
                PermissionLog.organization_id == organization_id,
                PermissionLog.tool == tool,
                PermissionLog.action == action,
                PermissionLog.decided_by.startswith("human:"),  # type: ignore[union-attr]
                PermissionLog.created_at >= cutoff,  # type: ignore[operator]
            )
        ).all()

    if not logs:
        return None

    # Filter to matching scope (fnmatch for glob support)
    matching = [log for log in logs if fnmatch.fnmatch(scope, log.scope)]
    if not matching:
        return None

    allow_count = sum(1 for d in matching if d.decision == PermissionDecision.ALLOW)
    deny_count = sum(1 for d in matching if d.decision == PermissionDecision.DENY)
    total = len(matching)
    allow_rate = allow_count / total if total else 0.0

    humans = {d.decided_by for d in matching}

    timestamps = [d.created_at for d in matching]
    last_at = max(timestamps)
    first_at = min(timestamps)

    trend = compute_trend(matching)
    velocity = _compute_velocity(matching, lookback_days)

    return OrgSignal(
        total_decisions=total,
        allow_count=allow_count,
        deny_count=deny_count,
        allow_rate=allow_rate,
        unique_humans=len(humans),
        last_decision_at=last_at,
        first_decision_at=first_at,
        trend=trend,
        velocity=velocity,
    )


def compute_trend(decisions: list[PermissionLog]) -> str:
    """Analyze whether decisions are trending toward approve or deny.

    Splits decision history into two time halves and compares allow rates.

    Returns:
        "toward_approve" | "toward_deny" | "stable" | "mixed" | "new" | "insufficient_data"
    """
    if len(decisions) < 4:
        return "insufficient_data"

    sorted_decisions = sorted(decisions, key=lambda d: d.created_at)

    # Check if all decisions are very recent (within 24h)
    time_span = (sorted_decisions[-1].created_at - sorted_decisions[0].created_at).total_seconds()
    if time_span < 86400:  # 24 hours
        return "new"

    # Split into older and recent halves
    midpoint = len(sorted_decisions) // 2
    older = sorted_decisions[:midpoint]
    recent = sorted_decisions[midpoint:]

    older_rate = sum(1 for d in older if d.decision == PermissionDecision.ALLOW) / len(older)
    recent_rate = sum(1 for d in recent if d.decision == PermissionDecision.ALLOW) / len(recent)

    threshold = 0.15  # minimum shift to call it a trend

    if recent_rate > older_rate + threshold:
        return "toward_approve"
    elif recent_rate < older_rate - threshold:
        return "toward_deny"

    # Check for stability
    overall_rate = sum(1 for d in sorted_decisions if d.decision == PermissionDecision.ALLOW) / len(sorted_decisions)
    if overall_rate > 0.9 or overall_rate < 0.1:
        return "stable"

    return "mixed"


def compute_auto_approve_distance(
    org_signal: OrgSignal,
    min_decisions: int,
    threshold: float,
) -> int | None:
    """Calculate how many more consistent allows are needed to reach auto-approve.

    Returns None if already auto-approved, threshold unreachable, or trending toward deny.
    """
    if org_signal.trend == "toward_deny":
        return None

    current_total = org_signal.total_decisions
    current_allows = org_signal.allow_count

    # Already past threshold with enough decisions
    if current_total >= min_decisions and (current_allows / current_total) >= threshold:
        return 0

    # Simulate adding more allow decisions until threshold is met
    for additional in range(1, 200):
        new_total = current_total + additional
        new_allows = current_allows + additional
        if new_total >= min_decisions and (new_allows / new_total) >= threshold:
            return additional

    return None  # unreachable within 200 more decisions


def _compute_velocity(decisions: list[PermissionLog], lookback_days: int) -> float:
    """Compute decisions per day."""
    if not decisions:
        return 0.0

    timestamps = [d.created_at for d in decisions]
    span_days = (max(timestamps) - min(timestamps)).total_seconds() / 86400

    if span_days < 1.0:
        # All decisions in less than a day — use lookback period for rate
        return len(decisions) / max(lookback_days, 1)

    return len(decisions) / span_days
