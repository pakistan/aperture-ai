"""AIperture MCP Server — exposes 10 read-only/append-only tools for
permission checking, artifact storage, and audit trail via MCP.

approve_action, deny_action, revoke_permission_pattern, and
report_tool_execution are intentionally NOT exposed as MCP tools.
An MCP caller (the AI agent) has direct access to both check_permission
and approve/deny — it can relay the HMAC challenge token to self-approve
without human involvement. The HMAC prevents *forgery* but not *relay*.
For Claude Code, use the hook-based integration (PermissionRequest +
PostToolUse) where Claude Code's native permission dialog is the human gate.
For other runtimes with their own UI layer, use the HTTP API.

When running as ``aiperture mcp-serve``, an embedded HTTP server for
Claude Code hooks is started automatically on a background thread
(default port 8100) so that ``aiperture serve`` is not required.

Usage:
    aiperture mcp-serve          # via CLI
    python -m aiperture.mcp_server  # direct

Claude Code integration:
    claude mcp add aiperture -- aiperture mcp-serve
"""

import json
import logging
import sys
import threading
from contextlib import asynccontextmanager

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from aiperture import plugins
from aiperture.db import init_db
from aiperture.permissions.engine import get_shared_engine
from aiperture.permissions.learning import PermissionLearner
from aiperture.stores.artifact_store import ArtifactStore
from aiperture.stores.audit_store import AuditStore

# Logging to stderr only — stdout is reserved for MCP protocol
import aiperture.config

logging.basicConfig(
    level=getattr(logging, aiperture.config.settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [aiperture] %(levelname)s %(message)s",
    stream=sys.stderr,
)
aiperture.config.setup_file_logging()
logger = logging.getLogger(__name__)

_hooks_server_thread: threading.Thread | None = None


def _start_hooks_server() -> None:
    """Start a lightweight HTTP server for Claude Code hooks on a daemon thread.

    Uses the same hooks router as ``aiperture serve`` but in a minimal FastAPI
    app so that no separate terminal is needed.  Binds to localhost only.
    """
    import uvicorn
    from fastapi import FastAPI

    from aiperture.api.routes.hooks import router as hooks_router

    app = FastAPI()
    app.include_router(hooks_router, prefix="/hooks")

    # Suppress uvicorn access logs to avoid polluting MCP stdio
    uv_config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=aiperture.config.settings.api_port,
        log_level="warning",
    )
    server = uvicorn.Server(uv_config)

    # Run in a daemon thread — dies when the MCP process exits
    thread = threading.Thread(target=server.run, daemon=True, name="aiperture-hooks")
    thread.start()
    logger.info(
        "Embedded hooks server started on 127.0.0.1:%d",
        aiperture.config.settings.api_port,
    )
    return thread


@asynccontextmanager
async def lifespan(server: FastMCP):
    """Initialize database, plugins, and embedded hooks server on startup."""
    global _hooks_server_thread
    plugins.load_all()
    init_db()
    # Register plugin MCP tools if any
    plugin_tools = plugins.get("mcp_tools")
    if plugin_tools is not None:
        plugin_tools.register_tools(mcp)
    # Start embedded hooks HTTP server for Claude Code learning
    try:
        _hooks_server_thread = _start_hooks_server()
    except Exception:
        logger.warning("Could not start embedded hooks server — learning via hooks disabled", exc_info=True)
    logger.info("AIperture MCP server ready")
    yield {}
    logger.info("AIperture MCP server shutting down")


mcp = FastMCP(
    name="aiperture",
    lifespan=lifespan,
)

# Shared instances
_engine = get_shared_engine()
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
    content_hash: str = "",
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
        content_hash: Optional SHA-256 hash of content being written/modified.
            Different hashes are treated as separate checks even for the same scope.
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
        content_hash=content_hash,
    )

    details = verdict.to_dict()
    details["tool"] = tool
    details["action"] = action
    details["scope"] = scope
    details["session_id"] = session_id

    _audit.record(
        event_type="permission.check",
        summary=f"{verdict.decision}: {tool}.{action} on {scope}",
        organization_id=organization_id,
        entity_type="permission",
        entity_id=f"{tool}.{action}.{scope}",
        actor_type="runtime",
        runtime_id="mcp",
        details=details,
    )

    return json.dumps(verdict.to_dict(), indent=2)


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
    from aiperture.permissions.explainer import explain_action as _explain
    from aiperture.permissions.risk import classify_risk

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
    """View what AIperture has learned from human permission decisions.

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
        return "No permission patterns learned yet. AIperture needs more human decisions to detect patterns."

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
    stored here. AIperture SHA-256 hashes the content for integrity
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
    """Get the audit trail — everything that happened in AIperture.

    Every permission check, every artifact stored, every human decision
    is logged here. Use this for compliance review or debugging.

    Args:
        organization_id: Tenant identifier
        event_type: Filter by type (e.g. "permission.check", "artifact.stored")
        entity_id: Filter by entity ID
        limit: Maximum number of events to return
    """
    limit = min(limit, 500)
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
    """Get current AIperture configuration (tunable settings only).

    Returns the 14 tunable settings with their current values and descriptions.
    Infrastructure settings (db_path, api_host, etc.) are not exposed.
    """
    import aiperture.config

    return json.dumps({
        "settings": aiperture.config.get_tunable_config(),
        "descriptions": dict(aiperture.config.Settings.TUNABLE_DESCRIPTIONS),
    }, indent=2)


# ─── Compliance Tools ────────────────────────────────────────────


@mcp.tool()
def get_compliance_report(
    session_id: str = "",
    organization_id: str = "default",
) -> str:
    """Get a compliance report showing checked vs. unchecked tool executions.

    Returns:
    - Total executions reported
    - Executions with prior permission check
    - Executions WITHOUT prior permission check (compliance gaps)
    - Compliance ratio

    Args:
        session_id: Filter to a specific session
        organization_id: Tenant identifier
    """
    report = _compute_compliance(session_id, organization_id)
    return json.dumps(report, indent=2)


def _compute_compliance(session_id: str, organization_id: str) -> dict:
    """Compare permission checks against tool executions for a session."""
    checks = _audit.list_events(
        organization_id=organization_id,
        event_type="permission.check",
        limit=1000,
    )
    executions = _audit.list_events(
        organization_id=organization_id,
        event_type="tool.executed",
        limit=1000,
    )

    # Filter by session_id from details
    if session_id:
        checks = [e for e in checks if e.details and e.details.get("session_id") == session_id]
        executions = [e for e in executions if e.details and e.details.get("session_id") == session_id]

    # Build sets of (tool, action, scope) for each
    checked_keys = set()
    for e in checks:
        if e.details:
            t = e.details.get("tool", "")
            a = e.details.get("action", "")
            s = e.details.get("scope", "")
            if t and a:
                checked_keys.add((t, a, s))

    # Also extract from entity_id for check events that store verdict directly
    for e in checks:
        if e.entity_id and e.entity_id.count(".") >= 2:
            parts = e.entity_id.split(".", 2)
            checked_keys.add((parts[0], parts[1], parts[2]))

    executed_keys = set()
    for e in executions:
        if e.details:
            t = e.details.get("tool", "")
            a = e.details.get("action", "")
            s = e.details.get("scope", "")
            if t and a:
                executed_keys.add((t, a, s))

    unchecked = executed_keys - checked_keys
    total = len(executed_keys)
    checked = len(executed_keys & checked_keys)

    return {
        "total_executions": total,
        "checked_executions": checked,
        "unchecked_executions": len(unchecked),
        "compliance_ratio": round(checked / total, 3) if total > 0 else 1.0,
        "unchecked_details": [
            {"tool": t, "action": a, "scope": s} for t, a, s in sorted(unchecked)
        ],
    }


# ─── Pattern Inspection Tools ────────────────────────────────────


@mcp.tool()
def list_auto_approved_patterns(
    organization_id: str = "default",
    min_decisions: int = 0,
) -> str:
    """List all permission patterns currently being auto-approved.

    Shows which (tool, action, scope) patterns have enough consistent
    human approvals to trigger automatic approval. Use this to identify
    patterns you may want to revoke.

    Args:
        organization_id: Tenant identifier
        min_decisions: Minimum decisions to include (0 = use configured threshold)
    """
    import aiperture.config

    settings = aiperture.config.settings
    if not settings.permission_learning_enabled:
        return json.dumps({"patterns": [], "message": "Learning is disabled"})

    threshold_min = min_decisions or settings.permission_learning_min_decisions
    threshold_rate = settings.auto_approve_threshold

    patterns = _learner.detect_patterns(
        organization_id=organization_id,
        min_decisions=threshold_min,
    )

    auto_approved = [
        p for p in patterns
        if p.approval_rate >= threshold_rate
    ]

    if not auto_approved:
        return json.dumps({"patterns": [], "message": "No patterns currently auto-approved"})

    return json.dumps({
        "patterns": [
            {
                "tool": p.tool,
                "action": p.action,
                "scope": p.scope,
                "approval_rate": round(p.approval_rate, 3),
                "total_decisions": p.total_decisions,
                "unique_humans": p.unique_humans,
                "confidence": round(p.confidence, 3),
            }
            for p in auto_approved
        ],
        "count": len(auto_approved),
        "threshold": {
            "min_decisions": threshold_min,
            "approval_rate": threshold_rate,
        },
    })


# ─── Entry Point ─────────────────────────────────────────────────────


def serve():
    """Run the MCP server on stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    serve()
