"""Permission API — check, grant, record, and learn.

External runtimes call these endpoints to:
1. Check if an action is permitted (with optional enrichment)
2. Record a human's decision
3. Grant task-scoped permissions
4. View learned patterns
5. Find similar patterns
6. Get command explanations
"""


from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from aperture.models.permission import Permission, PermissionDecision
from aperture.permissions.engine import PermissionEngine
from aperture.permissions.learning import PermissionLearner

router = APIRouter()
engine = PermissionEngine()
learner = PermissionLearner()


# --- Request/Response schemas ---


class CheckRequest(BaseModel):
    tool: str
    action: str
    scope: str
    permissions: list[Permission]  # static rules for this agent
    task_id: str = ""
    session_id: str = ""
    organization_id: str = "default"
    runtime_id: str = ""
    content_hash: str = ""  # optional content awareness


class RecordDecisionRequest(BaseModel):
    tool: str
    action: str
    scope: str
    decision: PermissionDecision
    decided_by: str  # user identifier
    challenge: str = ""
    challenge_nonce: str = ""
    challenge_issued_at: float = 0.0
    task_id: str = ""
    session_id: str = ""
    organization_id: str = "default"
    runtime_id: str = ""
    reasoning: str = ""


class GrantRequest(BaseModel):
    task_id: str
    tool: str
    action: str
    scope: str
    decision: PermissionDecision
    granted_by: str
    organization_id: str = "default"
    ttl_seconds: int | None = None


# --- Endpoints ---


@router.post("/check")
def check_permission(req: CheckRequest, enrich: bool = False):
    """Check if an AI agent action is permitted.

    Resolution order:
    1. Session memory (if session_id provided)
    2. Task-scoped grants (ReBAC)
    3. Learned auto-decisions (from human patterns)
    4. Static permission rules (glob matching)
    5. Default deny

    Set ?enrich=true to get risk tier, explanation, crowd signal, and similar patterns.
    """
    verdict = engine.check(
        tool=req.tool,
        action=req.action,
        scope=req.scope,
        permissions=req.permissions,
        task_id=req.task_id,
        session_id=req.session_id,
        organization_id=req.organization_id,
        runtime_id=req.runtime_id,
        enrich=enrich,
        content_hash=req.content_hash,
    )
    return verdict.to_dict()


@router.post("/record")
def record_decision(req: RecordDecisionRequest):
    """Record a human's permission decision for learning.

    Every decision is persisted. Over time, the system learns
    which actions to auto-approve and which to always flag.
    """
    try:
        log = engine.record_human_decision(
            tool=req.tool,
            action=req.action,
            scope=req.scope,
            decision=req.decision,
            decided_by=req.decided_by,
            challenge=req.challenge,
            challenge_nonce=req.challenge_nonce,
            challenge_issued_at=req.challenge_issued_at,
            task_id=req.task_id,
            session_id=req.session_id,
            organization_id=req.organization_id,
            runtime_id=req.runtime_id,
            reasoning=req.reasoning,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"recorded": True, "log_id": log.id}


@router.post("/grant")
def grant_task_permission(req: GrantRequest):
    """Grant a task-scoped permission (ReBAC).

    Used when a human approves an action for a specific task.
    Optionally expires after ttl_seconds.
    """
    grant = engine.grant_task_permission(
        task_id=req.task_id,
        tool=req.tool,
        action=req.action,
        scope=req.scope,
        decision=req.decision,
        granted_by=req.granted_by,
        organization_id=req.organization_id,
        ttl_seconds=req.ttl_seconds,
    )
    return {"granted": True, "permission_id": grant.permission_id}


@router.get("/patterns")
def get_patterns(
    organization_id: str = "default",
    min_decisions: int = 5,
    lookback_days: int = 90,
    limit: int = 50,
):
    """View learned permission patterns.

    Shows which (tool, action, scope) combinations the system
    has learned to auto-approve, auto-deny, or flag for review.
    """
    patterns = learner.detect_patterns(
        organization_id=organization_id,
        min_decisions=min_decisions,
        lookback_days=lookback_days,
        limit=limit,
    )
    return {
        "patterns": [
            {
                "tool": p.tool,
                "action": p.action,
                "scope": p.scope,
                "total_decisions": p.total_decisions,
                "approval_rate": round(p.approval_rate, 3),
                "weighted_approval_rate": round(p.weighted_approval_rate, 3),
                "recommendation": p.recommendation,
                "recommendation_text": p.recommendation_text,
                "confidence": round(p.confidence, 3),
                "unique_humans": p.unique_humans,
            }
            for p in patterns
        ],
        "count": len(patterns),
    }


@router.get("/stats")
def get_stats(organization_id: str = "default", lookback_days: int = 30):
    """Permission decision statistics."""
    return learner.get_stats(organization_id=organization_id, lookback_days=lookback_days)


@router.get("/similar")
def get_similar(
    tool: str,
    action: str,
    scope: str,
    organization_id: str = "default",
    min_similarity: float = 0.5,
    limit: int = 5,
):
    """Find similar permission patterns with decision history."""
    from aperture.permissions.similarity import find_similar_patterns

    patterns = find_similar_patterns(
        tool=tool, action=action, scope=scope,
        organization_id=organization_id,
        min_similarity=min_similarity, limit=limit,
    )
    return {
        "patterns": [
            {
                "tool": p.tool,
                "action": p.action,
                "scope": p.scope,
                "similarity": round(p.similarity, 3),
                "allow_rate": round(p.allow_rate, 3),
                "total_decisions": p.total_decisions,
                "unique_humans": p.unique_humans,
            }
            for p in patterns
        ],
        "count": len(patterns),
    }


@router.get("/explain")
def explain(tool: str, action: str, scope: str):
    """Get a human-readable explanation of what an action does, with risk assessment."""
    from aperture.permissions.explainer import explain_action
    from aperture.permissions.risk import classify_risk

    risk = classify_risk(tool, action, scope)
    explanation = explain_action(tool, action, scope, risk)
    return {
        "explanation": explanation,
        "risk": {
            "tier": risk.tier.value,
            "score": round(risk.score, 3),
            "factors": risk.factors,
            "reversible": risk.reversible,
        },
    }
