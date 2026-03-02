"""Permission verdict models — rich responses replacing bare allow/deny/ask.

Every permission check returns a PermissionVerdict with risk assessment,
command explanation, crowd signals, similar patterns, and actionable context.
"""

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from aperture.models.permission import PermissionDecision


class RiskTier(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RiskAssessment:
    """Deterministic risk classification of a (tool, action, scope) triple."""

    tier: RiskTier
    score: float  # 0.0-1.0
    factors: list[str] = field(default_factory=list)  # ["destructive_action", "broad_scope"]
    reversible: bool = True


@dataclass
class OrgSignal:
    """Crowd signal from this organization's decision history."""

    total_decisions: int
    allow_count: int
    deny_count: int
    allow_rate: float
    unique_humans: int
    trend: str  # "toward_approve" | "toward_deny" | "stable" | "mixed" | "new" | "insufficient_data"
    velocity: float  # decisions per day
    last_decision_at: Optional[datetime] = None
    first_decision_at: Optional[datetime] = None


@dataclass
class SimilarPattern:
    """A structurally similar permission pattern with decision history."""

    tool: str
    action: str
    scope: str
    similarity: float  # 0.0-1.0
    allow_rate: float
    total_decisions: int
    unique_humans: int = 0


@dataclass
class GlobalSignal:
    """Cross-organization anonymized intelligence (differential privacy protected)."""

    total_orgs: int
    estimated_allow_rate: float
    confidence_interval: tuple[float, float]  # (low, high)
    sample_size: int


@dataclass
class PermissionVerdict:
    """Rich permission response — replaces bare PermissionDecision enum.

    Backward compatible: verdict.decision still gives ALLOW/DENY/ASK.
    """

    # Core decision (backward compatible — PermissionDecision is a str enum)
    decision: PermissionDecision
    decided_by: str  # "static_rule" / "auto_learned" / "rebac" / "session_memory"

    # Risk assessment
    risk: RiskAssessment = field(default_factory=lambda: RiskAssessment(
        tier=RiskTier.MEDIUM, score=0.5,
    ))

    # Command explanation
    explanation: str = ""

    # Crowd signal from this org
    org_signal: OrgSignal | None = None

    # Similar patterns (when no exact match)
    similar_patterns: list[SimilarPattern] = field(default_factory=list)

    # Cross-org intelligence
    global_signal: GlobalSignal | None = None

    # Actionable context
    auto_approve_distance: int | None = None  # "7 more allows → automatic" or None
    recommendation: str = ""  # human-readable action suggestion
    recommendation_code: str = "keep_asking"  # "auto_approve" / "review" / "keep_asking" / "suggest_rule" / "caution"

    def to_dict(self) -> dict:
        """Serialize to JSON-compatible dict."""
        result = {
            "decision": self.decision.value,
            "decided_by": self.decided_by,
            "risk": {
                "tier": self.risk.tier.value,
                "score": round(self.risk.score, 3),
                "factors": self.risk.factors,
                "reversible": self.risk.reversible,
            },
            "explanation": self.explanation,
            "recommendation": self.recommendation,
            "recommendation_code": self.recommendation_code,
        }

        if self.org_signal:
            result["org_signal"] = {
                "total_decisions": self.org_signal.total_decisions,
                "allow_count": self.org_signal.allow_count,
                "deny_count": self.org_signal.deny_count,
                "allow_rate": round(self.org_signal.allow_rate, 3),
                "unique_humans": self.org_signal.unique_humans,
                "last_decision_at": self.org_signal.last_decision_at.isoformat() if self.org_signal.last_decision_at else None,
                "first_decision_at": self.org_signal.first_decision_at.isoformat() if self.org_signal.first_decision_at else None,
                "trend": self.org_signal.trend,
                "velocity": round(self.org_signal.velocity, 2),
            }

        if self.similar_patterns:
            result["similar_patterns"] = [
                {
                    "tool": p.tool,
                    "action": p.action,
                    "scope": p.scope,
                    "similarity": round(p.similarity, 3),
                    "allow_rate": round(p.allow_rate, 3),
                    "total_decisions": p.total_decisions,
                    "unique_humans": p.unique_humans,
                }
                for p in self.similar_patterns
            ]

        if self.global_signal:
            result["global_signal"] = {
                "total_orgs": self.global_signal.total_orgs,
                "estimated_allow_rate": round(self.global_signal.estimated_allow_rate, 3),
                "confidence_interval": [
                    round(self.global_signal.confidence_interval[0], 3),
                    round(self.global_signal.confidence_interval[1], 3),
                ],
                "sample_size": self.global_signal.sample_size,
            }

        if self.auto_approve_distance is not None:
            result["auto_approve_distance"] = self.auto_approve_distance

        return result
