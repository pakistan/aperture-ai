"""Aperture MCP Server — exposes permission checking, artifact storage,
and audit trail as MCP tools for Claude Code and any MCP-compatible runtime.

Usage:
    aperture mcp-serve          # via CLI
    python -m aperture.mcp_server  # direct

Claude Code integration:
    claude mcp add aperture -- aperture mcp-serve
"""

import json
import logging
import sys
from contextlib import asynccontextmanager

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from aperture.db import init_db
from aperture.models.permission import Permission, PermissionDecision
from aperture.permissions.engine import PermissionEngine
from aperture.permissions.intelligence import IntelligenceEngine
from aperture.permissions.learning import PermissionLearner
from aperture.stores.artifact_store import ArtifactStore
from aperture.stores.audit_store import AuditStore

# Logging to stderr only — stdout is reserved for MCP protocol
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [aperture] %(levelname)s %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(server: FastMCP):
    """Initialize database on startup."""
    init_db()
    logger.info("Aperture MCP server ready")
    yield {}
    logger.info("Aperture MCP server shutting down")


mcp = FastMCP(
    name="aperture",
    lifespan=lifespan,
)

# Shared instances
_engine = PermissionEngine()
_intelligence = IntelligenceEngine()
_learner = PermissionLearner()
_artifacts = ArtifactStore()
_audit = AuditStore()


# ─── Permission Tools ────────────────────────────────────────────────


@mcp.tool()
def check_permission(
    tool: str,
    action: str,
    scope: str,
    task_id: str = "",
    session_id: str = "",
    organization_id: str = "default",
) -> str:
    """Check if an AI agent action is permitted.

    Returns an enriched verdict with:
    - decision: "allow", "deny", or "ask"
    - risk: tier (low/medium/high/critical), score, factors, reversibility
    - explanation: human-readable description of what the action does
    - org_signal: how many people in your org allowed/denied this (if history exists)
    - similar_patterns: related patterns with decision history (if no exact match)
    - recommendation: actionable suggestion

    Args:
        tool: Tool name (e.g. "filesystem", "shell", "api")
        action: Action name (e.g. "read", "write", "execute", "delete")
        scope: Resource scope (e.g. "src/main.py", "production/*", "rm -rf ./build/")
        task_id: Optional task ID for task-scoped permission grants
        session_id: Optional session ID for session memory (don't re-ask)
        organization_id: Tenant identifier
    """
    verdict = _engine.check(
        tool=tool,
        action=action,
        scope=scope,
        permissions=[],  # no static rules via MCP — uses learned + task grants
        task_id=task_id,
        session_id=session_id,
        organization_id=organization_id,
        runtime_id="mcp",
        enrich=True,
    )

    _audit.record(
        event_type="permission.check",
        summary=f"{verdict.decision}: {tool}.{action} on {scope}",
        organization_id=organization_id,
        entity_type="permission",
        entity_id=f"{tool}.{action}.{scope}",
        actor_type="runtime",
        runtime_id="mcp",
        details=verdict.to_dict(),
    )

    return json.dumps(verdict.to_dict(), indent=2)


@mcp.tool()
def approve_action(
    tool: str,
    action: str,
    scope: str,
    decided_by: str,
    task_id: str = "",
    session_id: str = "",
    reasoning: str = "",
    organization_id: str = "default",
) -> str:
    """Record that a human approved an AI agent action.

    Call this when a human explicitly approves a tool call.
    The decision is persisted and used for future auto-learning.

    Args:
        tool: Tool name that was approved
        action: Action that was approved
        scope: Resource scope that was approved
        decided_by: Who approved it (user identifier)
        task_id: Optional task ID to also create a task-scoped grant
        session_id: Optional session ID (caches approval for this session)
        reasoning: Why the human approved (optional, helps with auditing)
        organization_id: Tenant identifier
    """
    _engine.record_human_decision(
        tool=tool,
        action=action,
        scope=scope,
        decision=PermissionDecision.ALLOW,
        decided_by=decided_by,
        task_id=task_id,
        session_id=session_id,
        organization_id=organization_id,
        runtime_id="mcp",
        reasoning=reasoning,
    )

    # Also grant task-scoped permission if task_id provided
    if task_id:
        _engine.grant_task_permission(
            task_id=task_id,
            tool=tool,
            action=action,
            scope=scope,
            decision=PermissionDecision.ALLOW,
            granted_by=decided_by,
            organization_id=organization_id,
        )

    # Report to cross-org intelligence (DP-protected)
    _intelligence.report_decision(tool, action, scope, decision_is_allow=True)

    return json.dumps({"recorded": True, "decision": "allow", "tool": tool, "scope": scope})


@mcp.tool()
def deny_action(
    tool: str,
    action: str,
    scope: str,
    decided_by: str,
    task_id: str = "",
    session_id: str = "",
    reasoning: str = "",
    organization_id: str = "default",
) -> str:
    """Record that a human denied an AI agent action.

    Call this when a human explicitly rejects a tool call.
    The denial is persisted and used for future auto-learning.

    Args:
        tool: Tool name that was denied
        action: Action that was denied
        scope: Resource scope that was denied
        decided_by: Who denied it (user identifier)
        task_id: Optional task ID
        session_id: Optional session ID (caches denial for this session)
        reasoning: Why the human denied (optional, helps with auditing)
        organization_id: Tenant identifier
    """
    _engine.record_human_decision(
        tool=tool,
        action=action,
        scope=scope,
        decision=PermissionDecision.DENY,
        decided_by=decided_by,
        task_id=task_id,
        session_id=session_id,
        organization_id=organization_id,
        runtime_id="mcp",
        reasoning=reasoning,
    )

    # Report to cross-org intelligence (DP-protected)
    _intelligence.report_decision(tool, action, scope, decision_is_allow=False)

    return json.dumps({"recorded": True, "decision": "deny", "tool": tool, "scope": scope})


@mcp.tool()
def explain_action(
    tool: str,
    action: str,
    scope: str,
) -> str:
    """Get a human-readable explanation of what an action does, with risk assessment.

    Use this to understand what a tool call will do before approving or denying it.

    Args:
        tool: Tool name (e.g. "shell", "filesystem")
        action: Action name (e.g. "execute", "delete")
        scope: Resource scope (e.g. "rm -rf ./build/", "src/main.py")
    """
    from aperture.permissions.explainer import explain_action as _explain
    from aperture.permissions.risk import classify_risk

    risk = classify_risk(tool, action, scope)
    explanation = _explain(tool, action, scope, risk)

    return json.dumps({
        "explanation": explanation,
        "risk": {
            "tier": risk.tier.value,
            "score": round(risk.score, 3),
            "factors": risk.factors,
            "reversible": risk.reversible,
        },
    }, indent=2)


@mcp.tool()
def get_permission_patterns(
    organization_id: str = "default",
    min_decisions: int = 5,
) -> str:
    """View what Aperture has learned from human permission decisions.

    Shows which tool/action/scope combinations are being auto-approved,
    auto-denied, or still need human review.

    Args:
        organization_id: Tenant identifier
        min_decisions: Minimum number of decisions to form a pattern
    """
    patterns = _learner.detect_patterns(
        organization_id=organization_id,
        min_decisions=min_decisions,
    )

    if not patterns:
        return "No permission patterns learned yet. Aperture needs more human decisions to detect patterns."

    lines = ["Learned permission patterns:\n"]
    for p in patterns:
        status = {
            "auto_approve": "AUTO-APPROVE",
            "auto_deny": "AUTO-DENY",
            "review": "NEEDS REVIEW",
            "keep_asking": "ASKING",
            "suggest_rule": "SUGGEST RULE",
            "caution": "CAUTION",
        }.get(p.recommendation, p.recommendation)

        lines.append(
            f"  [{status}] {p.tool}.{p.action} on {p.scope} "
            f"({p.approval_rate:.0%} approved, {p.total_decisions} decisions, "
            f"{p.unique_humans} reviewers)"
        )
        if p.recommendation_text:
            lines.append(f"    → {p.recommendation_text}")

    return "\n".join(lines)


# ─── Artifact Tools ──────────────────────────────────────────────────


@mcp.tool()
def store_artifact(
    content: str,
    tool_name: str = "",
    summary: str = "",
    task_id: str = "",
    artifact_type: str = "custom",
    tokens_input: int = 0,
    tokens_output: int = 0,
    cost_usd: float = 0.0,
    model_used: str = "",
    provider_used: str = "",
    organization_id: str = "default",
) -> str:
    """Store an AI agent output as a verified artifact.

    Every tool call result, LLM response, or generated file should be
    stored here. Aperture SHA-256 hashes the content for integrity
    verification and creates an immutable audit trail.

    Args:
        content: The output content to store
        tool_name: Which tool produced this (e.g. "shell", "filesystem")
        summary: Human-readable summary of what this artifact is
        task_id: Task this artifact belongs to
        artifact_type: Type: "tool_call", "llm_response", "file", "decision", "custom"
        tokens_input: Input tokens used (if LLM response)
        tokens_output: Output tokens used (if LLM response)
        cost_usd: Cost in USD (if known)
        model_used: Which model produced this (e.g. "claude-sonnet-4-5")
        provider_used: Which provider (e.g. "anthropic", "openai")
        organization_id: Tenant identifier
    """
    artifact = _artifacts.store(
        content=content,
        artifact_type=artifact_type,
        organization_id=organization_id,
        task_id=task_id,
        runtime_id="mcp",
        tool_name=tool_name,
        summary=summary,
        tokens_input=tokens_input,
        tokens_output=tokens_output,
        cost_usd=cost_usd,
        model_used=model_used,
        provider_used=provider_used,
    )

    _audit.record(
        event_type="artifact.stored",
        summary=f"Stored {artifact_type}: {summary or tool_name or artifact.artifact_id}",
        organization_id=organization_id,
        entity_type="artifact",
        entity_id=artifact.artifact_id,
        actor_type="runtime",
        runtime_id="mcp",
        details={
            "artifact_id": artifact.artifact_id,
            "content_hash": artifact.content_hash,
            "type": artifact_type,
            "tool_name": tool_name,
        },
    )

    return json.dumps({
        "artifact_id": artifact.artifact_id,
        "content_hash": artifact.content_hash,
        "verification_status": artifact.verification_status,
    })


@mcp.tool()
def verify_artifact(artifact_id: str) -> str:
    """Re-verify an artifact's integrity by recomputing its SHA-256 hash.

    Use this to confirm that a stored artifact has not been tampered with.

    Args:
        artifact_id: The artifact ID to verify
    """
    try:
        artifact = _artifacts.verify(artifact_id)
    except ValueError as e:
        raise ToolError(str(e))

    return json.dumps({
        "artifact_id": artifact.artifact_id,
        "verification_status": artifact.verification_status,
        "content_hash": artifact.content_hash,
    })


@mcp.tool()
def get_cost_summary(
    organization_id: str = "default",
    task_id: str = "",
) -> str:
    """Get a cost summary across all stored artifacts.

    Shows total tokens, cost in USD, and breakdown by provider and model.

    Args:
        organization_id: Tenant identifier
        task_id: Optional task ID to scope the summary
    """
    summary = _artifacts.get_cost_summary(
        organization_id=organization_id,
        task_id=task_id or None,
    )
    return json.dumps(summary, indent=2)


# ─── Audit Tools ─────────────────────────────────────────────────────


@mcp.tool()
def get_audit_trail(
    organization_id: str = "default",
    event_type: str = "",
    entity_id: str = "",
    limit: int = 20,
) -> str:
    """Get the audit trail — everything that happened in Aperture.

    Every permission check, every artifact stored, every human decision
    is logged here. Use this for compliance review or debugging.

    Args:
        organization_id: Tenant identifier
        event_type: Filter by type (e.g. "permission.check", "artifact.stored")
        entity_id: Filter by entity ID
        limit: Maximum number of events to return
    """
    events = _audit.list_events(
        organization_id=organization_id,
        event_type=event_type or None,
        entity_id=entity_id or None,
        limit=limit,
    )

    if not events:
        return "No audit events found."

    lines = [f"Audit trail ({len(events)} events):\n"]
    for e in events:
        lines.append(
            f"  [{e.event_type}] {e.summary} "
            f"(actor={e.actor_type}, runtime={e.runtime_id}, "
            f"at={e.created_at.isoformat()})"
        )

    return "\n".join(lines)


# ─── Config Tools ────────────────────────────────────────────────────


@mcp.tool()
def get_config() -> str:
    """Get current Aperture configuration (tunable settings only).

    Returns the 7 tunable settings with their current values and descriptions.
    Infrastructure settings (db_path, api_host, etc.) are not exposed.
    """
    import aperture.config

    return json.dumps({
        "settings": aperture.config.get_tunable_config(),
        "descriptions": dict(aperture.config.Settings.TUNABLE_DESCRIPTIONS),
    }, indent=2)


@mcp.tool()
def update_config(
    permission_learning_enabled: bool | None = None,
    permission_learning_min_decisions: int | None = None,
    auto_approve_threshold: float | None = None,
    auto_deny_threshold: float | None = None,
    intelligence_enabled: bool | None = None,
    intelligence_epsilon: float | None = None,
    intelligence_min_orgs: int | None = None,
) -> str:
    """Update Aperture configuration at runtime.

    Only provide the settings you want to change. Omitted settings keep
    their current values. Changes are persisted to .aperture.env and
    take effect immediately (no restart needed).

    Args:
        permission_learning_enabled: Auto-learn from human decisions
        permission_learning_min_decisions: Min decisions before auto-deciding
        auto_approve_threshold: Approval rate (0.0-1.0) to auto-approve
        auto_deny_threshold: Approval rate (0.0-1.0) to auto-deny
        intelligence_enabled: Enable cross-org DP intelligence
        intelligence_epsilon: DP noise level (higher = less private)
        intelligence_min_orgs: Min orgs for global signal
    """
    import aperture.config

    updates = {}
    if permission_learning_enabled is not None:
        updates["permission_learning_enabled"] = permission_learning_enabled
    if permission_learning_min_decisions is not None:
        updates["permission_learning_min_decisions"] = permission_learning_min_decisions
    if auto_approve_threshold is not None:
        updates["auto_approve_threshold"] = auto_approve_threshold
    if auto_deny_threshold is not None:
        updates["auto_deny_threshold"] = auto_deny_threshold
    if intelligence_enabled is not None:
        updates["intelligence_enabled"] = intelligence_enabled
    if intelligence_epsilon is not None:
        updates["intelligence_epsilon"] = intelligence_epsilon
    if intelligence_min_orgs is not None:
        updates["intelligence_min_orgs"] = intelligence_min_orgs

    if not updates:
        return json.dumps({
            "updated": False,
            "message": "No settings provided to update",
            "settings": aperture.config.get_tunable_config(),
        })

    try:
        aperture.config.update_settings(updates)
    except ValueError as e:
        raise ToolError(str(e))

    return json.dumps({
        "updated": True,
        "changed": list(updates.keys()),
        "settings": aperture.config.get_tunable_config(),
    })


# ─── Entry Point ─────────────────────────────────────────────────────


def serve():
    """Run the MCP server on stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    serve()
