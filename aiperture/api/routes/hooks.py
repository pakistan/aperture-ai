"""Claude Code hook endpoints — learn from native permission decisions.

Two endpoints handle the Claude Code hooks lifecycle:

1. POST /hooks/permission-request
   Called by Claude Code's PermissionRequest hook before showing the user a
   permission prompt. If AIperture has a learned ALLOW pattern, returns a
   hookSpecificOutput with decision.behavior="allow" to skip the prompt.
   Otherwise returns {} so Claude Code shows its normal prompt.

2. POST /hooks/post-tool-use
   Called by Claude Code's PostToolUse hook after a tool executes successfully.
   Records an implicit approval (the user saw and approved the tool call).
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel

from aiperture.hooks.pending_tracker import PendingRequest, PendingTracker
from aiperture.hooks.tool_mapping import map_tool
from aiperture.models.permission import PermissionDecision
from aiperture.models.verdict import RiskTier
from aiperture.permissions.engine import PermissionEngine
from aiperture.permissions.risk import classify_risk
from aiperture.stores.audit_store import AuditStore

logger = logging.getLogger(__name__)

router = APIRouter()
engine = PermissionEngine()
audit = AuditStore()
pending = PendingTracker()

# Track auto-approved tool calls so PostToolUse doesn't double-count them.
# Key: _pending_key(session_id, tool_name, tool_input), Value: True
_auto_approved: set[str] = set()
_MAX_AUTO_APPROVED = 10_000


def _pending_key(session_id: str, tool_name: str, tool_input: dict[str, Any]) -> str:
    """Build a composite key for correlating PermissionRequest with PostToolUse.

    PermissionRequest payloads do NOT include tool_use_id, so we hash
    (session_id, tool_name, tool_input) as a correlation key.
    """
    input_str = json.dumps(tool_input, sort_keys=True, default=str)
    digest = hashlib.sha256(f"{session_id}:{tool_name}:{input_str}".encode()).hexdigest()[:16]
    return digest


# --- Request schemas (Claude Code hook payloads) ---


class PermissionRequestPayload(BaseModel):
    """Claude Code PermissionRequest hook payload.

    Note: PermissionRequest does NOT include tool_use_id (per Claude Code docs).
    """
    tool_name: str = ""
    tool_input: dict[str, Any] = {}
    session_id: str = ""


class PostToolUsePayload(BaseModel):
    """Claude Code PostToolUse hook payload."""
    tool_name: str = ""
    tool_input: dict[str, Any] = {}
    tool_use_id: str = ""
    tool_response: Any = None
    session_id: str = ""


# --- Endpoints ---


@router.post("/permission-request")
def handle_permission_request(payload: PermissionRequestPayload):
    """Handle Claude Code PermissionRequest hook.

    If AIperture has a learned ALLOW pattern and risk is not HIGH/CRITICAL,
    returns hookSpecificOutput with decision.behavior="allow" to auto-approve.

    Otherwise returns {} so Claude Code shows its normal permission prompt,
    and tracks the request as pending for denial inference.
    """
    from aiperture.metrics import HOOK_PERMISSION_REQUESTS

    # Map Claude Code tool to AIperture triple
    mapping = map_tool(payload.tool_name, payload.tool_input)
    if mapping is None:
        # Skip AIperture's own tools
        return {}

    tool, action, scope = mapping
    pkey = _pending_key(payload.session_id, payload.tool_name, payload.tool_input)

    # Collect expired pending requests (piggybacked cleanup)
    _process_expired_denials()

    # Check learned patterns via the engine
    verdict = engine.check(
        tool=tool,
        action=action,
        scope=scope,
        permissions=[],  # No static rules — hooks rely on learned patterns only
        session_id=payload.session_id,
        organization_id="default",
        runtime_id="claude-code",
    )

    # Safety guard: never auto-approve HIGH/CRITICAL risk
    risk = classify_risk(tool, action, scope)
    if risk.tier in (RiskTier.HIGH, RiskTier.CRITICAL):
        HOOK_PERMISSION_REQUESTS.labels(decision="passthrough").inc()
        logger.debug(
            "Hook passthrough (high risk): %s.%s on %s [%s]",
            tool, action, scope, risk.tier.value,
        )
        pending.add(pkey, PendingRequest(
            tool=tool, action=action, scope=scope,
            session_id=payload.session_id, organization_id="default",
        ))
        return {}

    if verdict.decision == PermissionDecision.ALLOW:
        HOOK_PERMISSION_REQUESTS.labels(decision="allow").inc()
        logger.info(
            "Hook auto-approve: %s.%s on %s (decided_by=%s)",
            tool, action, scope, verdict.decided_by,
        )
        audit.record(
            "hook.auto_approve",
            f"Auto-approved {tool}.{action} on {scope}",
            entity_type="permission",
            entity_id=f"{tool}.{action}",
            actor_id="claude-code-hook",
            actor_type="hook",
            runtime_id="claude-code",
            details={"tool": tool, "action": action, "scope": scope,
                     "decided_by": verdict.decided_by},
        )
        # Track so PostToolUse doesn't double-count this as a human approval
        if len(_auto_approved) < _MAX_AUTO_APPROVED:
            _auto_approved.add(pkey)
        return {
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {
                    "behavior": "allow",
                },
            },
        }

    if verdict.decision == PermissionDecision.DENY:
        HOOK_PERMISSION_REQUESTS.labels(decision="deny").inc()
        logger.info(
            "Hook auto-deny: %s.%s on %s (decided_by=%s)",
            tool, action, scope, verdict.decided_by,
        )
        audit.record(
            "hook.auto_deny",
            f"Auto-denied {tool}.{action} on {scope}",
            entity_type="permission",
            entity_id=f"{tool}.{action}",
            actor_id="claude-code-hook",
            actor_type="hook",
            runtime_id="claude-code",
            details={"tool": tool, "action": action, "scope": scope,
                     "decided_by": verdict.decided_by},
        )
        return {
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {
                    "behavior": "deny",
                    "message": f"AIperture auto-denied: {tool}.{action} on {scope}",
                },
            },
        }

    # No opinion — let Claude Code show its normal prompt
    HOOK_PERMISSION_REQUESTS.labels(decision="passthrough").inc()
    logger.debug("Hook passthrough: %s.%s on %s", tool, action, scope)

    # Track as pending for denial inference
    pending.add(pkey, PendingRequest(
        tool=tool, action=action, scope=scope,
        session_id=payload.session_id, organization_id="default",
    ))

    return {}


@router.post("/post-tool-use")
def handle_post_tool_use(
    payload: PostToolUsePayload,
    background_tasks: BackgroundTasks,
):
    """Handle Claude Code PostToolUse hook.

    Records an implicit approval — the tool executed, which means the user
    approved it through Claude Code's native permission dialog.

    Skips recording if the tool was auto-approved by AIperture (to avoid
    double-counting).
    """
    from aiperture.metrics import HOOK_POST_TOOL_USE

    # Map Claude Code tool to AIperture triple
    mapping = map_tool(payload.tool_name, payload.tool_input)
    if mapping is None:
        return {"recorded": False, "reason": "skipped"}

    tool, action, scope = mapping
    HOOK_POST_TOOL_USE.inc()

    pkey = _pending_key(payload.session_id, payload.tool_name, payload.tool_input)

    # Resolve pending request (confirms user approved)
    pending.resolve(pkey)

    # Skip recording if this was auto-approved by AIperture
    if pkey in _auto_approved:
        _auto_approved.discard(pkey)
        return {"recorded": False, "reason": "auto_approved"}

    # Record implicit approval in background for speed
    background_tasks.add_task(
        _record_implicit_approval,
        tool=tool,
        action=action,
        scope=scope,
        session_id=payload.session_id,
    )

    return {"recorded": True}


def _record_implicit_approval(
    tool: str,
    action: str,
    scope: str,
    session_id: str,
) -> None:
    """Record an implicit approval from Claude Code's permission dialog."""
    try:
        engine.record_hook_decision(
            tool=tool,
            action=action,
            scope=scope,
            decision=PermissionDecision.ALLOW,
            session_id=session_id,
            organization_id="default",
            runtime_id="claude-code",
        )
    except Exception:
        logger.error(
            "Failed to record hook decision for %s.%s on %s",
            tool, action, scope, exc_info=True,
        )


def _process_expired_denials() -> None:
    """Process expired pending requests as inferred denials."""
    from aiperture.metrics import HOOK_INFERRED_DENIALS

    expired = pending.collect_expired()
    for req in expired:
        HOOK_INFERRED_DENIALS.inc()
        logger.info(
            "Inferred denial (timeout): %s.%s on %s",
            req.tool, req.action, req.scope,
        )
        try:
            engine.record_hook_decision(
                tool=req.tool,
                action=req.action,
                scope=req.scope,
                decision=PermissionDecision.DENY,
                session_id=req.session_id,
                organization_id=req.organization_id,
                runtime_id="claude-code",
            )
        except Exception:
            logger.error(
                "Failed to record inferred denial for %s.%s on %s",
                req.tool, req.action, req.scope, exc_info=True,
            )
