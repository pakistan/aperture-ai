"""Claude Code hook endpoints — learn from native permission decisions.

Three endpoints handle the Claude Code hooks lifecycle:

1. GET /hooks/session-start
   Called by Claude Code's SessionStart hook when a session begins.
   Returns a systemMessage (shown to user) and additionalContext (for Claude)
   with AIperture status: learned pattern count, learning status, config.

2. POST /hooks/permission-request
   Called by Claude Code's PermissionRequest hook before showing the user a
   permission prompt. If AIperture has a learned ALLOW pattern, returns a
   hookSpecificOutput with decision.behavior="allow" to skip the prompt.
   Otherwise returns {} so Claude Code shows its normal prompt.

3. POST /hooks/post-tool-use
   Called by Claude Code's PostToolUse hook after a tool executes successfully.
   Records an implicit approval (the user saw and approved the tool call).

These endpoints use Claude Code's hook payload format. Other runtimes use the
generic integration layer in aiperture.integrations.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
import threading
from typing import Any

from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel
from sqlmodel import Session, select

from aiperture.db import get_engine
from aiperture.hooks.pending_tracker import PendingRequest, PendingTracker
from aiperture.hooks.tool_mapping import map_tool
from aiperture.models.permission import PermissionDecision, PermissionLog
from aiperture.models.verdict import RiskTier
from aiperture.permissions.engine import get_shared_engine
from aiperture.permissions.learning import PermissionLearner
from aiperture.permissions.risk import classify_risk
from aiperture.project import detect_project_id
from aiperture.stores.audit_store import AuditStore

logger = logging.getLogger(__name__)

router = APIRouter()
engine = get_shared_engine()
audit = AuditStore()
pending = PendingTracker()

# Track auto-approved tool calls so PostToolUse doesn't double-count them.
# Key: _pending_key(session_id, tool_name, tool_input), Value: True
_auto_approved: set[str] = set()
_auto_approved_lock = threading.Lock()
_MAX_AUTO_APPROVED = 10_000


def _pending_key(session_id: str, tool_name: str, tool_input: dict[str, Any]) -> str:
    """Build a composite key for correlating PermissionRequest with PostToolUse.

    PermissionRequest payloads do NOT include tool_use_id, so we hash
    (session_id, tool_name, tool_input) as a correlation key.
    """
    input_str = json.dumps(tool_input, sort_keys=True, default=str)
    digest = hashlib.sha256(f"{session_id}:{tool_name}:{input_str}".encode()).hexdigest()[:16]
    return digest


def _learning_progress(
    tool: str,
    action: str,
    scope: str,
    organization_id: str,
    project_id: str,
) -> dict[str, Any] | None:
    """Compute how close a pattern is to auto-approve/deny.

    Returns dict with current_count, needed, approval_rate, status, message.
    Returns None on error or if learning is disabled.
    """
    import aiperture.config

    settings = aiperture.config.settings
    if not settings.permission_learning_enabled:
        return None

    min_decisions = settings.permission_learning_min_decisions
    approve_threshold = settings.auto_approve_threshold
    deny_threshold = settings.auto_deny_threshold

    try:
        with Session(get_engine()) as db:
            logs = db.exec(
                select(PermissionLog).where(
                    PermissionLog.organization_id == organization_id,
                    PermissionLog.project_id == project_id,
                    PermissionLog.tool == tool,
                    PermissionLog.action == action,
                    PermissionLog.decided_by.startswith("human:"),  # type: ignore[union-attr]
                    PermissionLog.revoked_at.is_(None),  # type: ignore[union-attr]
                )
            ).all()
    except Exception:
        return None

    matching = [
        log for log in logs
        if fnmatch.fnmatch(scope, log.scope) and not log.decided_by.endswith(":rapid")
    ]

    current = len(matching)
    if current == 0:
        return {
            "current_count": 0,
            "needed": min_decisions,
            "approval_rate": 0.0,
            "status": "new",
            "message": f"First approval recorded. {min_decisions} needed for auto-approve.",
        }

    allow_count = sum(1 for log in matching if log.decision == PermissionDecision.ALLOW)
    rate = allow_count / current if current else 0.0

    if current >= min_decisions and rate >= approve_threshold:
        return {
            "current_count": current,
            "needed": 0,
            "approval_rate": rate,
            "status": "auto_approve",
            "message": f"Pattern auto-approved ({current} decisions, {rate:.0%} approval rate).",
        }

    if current >= min_decisions and rate <= deny_threshold:
        return {
            "current_count": current,
            "needed": 0,
            "approval_rate": rate,
            "status": "auto_deny",
            "message": f"Pattern auto-denied ({current} decisions, {rate:.0%} approval rate).",
        }

    remaining = max(0, min_decisions - current)
    if remaining > 0:
        return {
            "current_count": current,
            "needed": remaining,
            "approval_rate": rate,
            "status": "learning",
            "message": f"{current}/{min_decisions} decisions recorded. {remaining} more needed for auto-approve.",
        }

    return {
        "current_count": current,
        "needed": 0,
        "approval_rate": rate,
        "status": "mixed",
        "message": f"{current} decisions at {rate:.0%} approval — not enough consensus for auto-approve ({approve_threshold:.0%} needed).",
    }


def _short_scope(scope: str, max_len: int = 60) -> str:
    """Truncate scope for display, preserving start and end."""
    if len(scope) <= max_len:
        return scope
    half = (max_len - 3) // 2
    return scope[:half] + "..." + scope[-half:]


# --- SessionStart endpoint ---


@router.get("/session-start")
def handle_session_start():
    """Handle Claude Code SessionStart hook.

    Returns a systemMessage (visible to user) with AIperture status,
    and additionalContext (for Claude) with operational details.
    """
    import aiperture.config

    settings = aiperture.config.settings
    learner = PermissionLearner()
    project_id = detect_project_id()

    # Count learned patterns (project-scoped + global)
    try:
        project_patterns = learner.detect_patterns(
            organization_id="default",
            project_id=project_id,
            min_decisions=settings.permission_learning_min_decisions,
        ) if project_id != "global" else []
        global_patterns = learner.detect_patterns(
            organization_id="default",
            project_id="global",
            min_decisions=settings.permission_learning_min_decisions,
        )
        patterns = project_patterns + global_patterns
        auto_approve = sum(
            1 for p in patterns
            if p.approval_rate >= settings.auto_approve_threshold
        )
        auto_deny = sum(
            1 for p in patterns
            if p.approval_rate <= settings.auto_deny_threshold
        )
    except Exception:
        logger.warning("Could not load patterns for session-start", exc_info=True)
        patterns = []
        auto_approve = 0
        auto_deny = 0

    # Build user-visible status line
    status_parts = []
    if auto_approve > 0:
        status_parts.append(f"{auto_approve} auto-approve")
    if auto_deny > 0:
        status_parts.append(f"{auto_deny} auto-deny")
    pattern_summary = " and ".join(status_parts) + " patterns" if status_parts else "no learned patterns yet"

    status_line = f"AIperture active — {pattern_summary}, project={project_id}"

    # Build context for Claude
    context_parts = [
        f"AIperture permission layer is active for project '{project_id}'.",
        f"{auto_approve} auto-approve and {auto_deny} auto-deny patterns learned.",
    ]
    if settings.permission_learning_enabled:
        context_parts.append(
            "New patterns are learned from human permission decisions via hooks."
        )
        context_parts.append(
            f"After {settings.permission_learning_min_decisions} consistent approvals, patterns auto-approve."
        )
    context_parts.append(
        "HIGH/CRITICAL risk actions are never auto-approved."
    )
    context_parts.append(
        "When AIperture auto-approves or learns from a decision, you will see status messages in the hook responses."
    )

    return {
        "systemMessage": status_line,
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": " ".join(context_parts),
        },
    }


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
    from aiperture.config import settings
    from aiperture.metrics import HOOK_PERMISSION_REQUESTS

    # Map Claude Code tool to AIperture triple
    mapping = map_tool(payload.tool_name, payload.tool_input)
    if mapping is None:
        # Skip AIperture's own tools
        return {}

    # Skip tools that Claude Code auto-allows (no learning needed)
    if payload.tool_name in settings.hook_auto_allowed_tools_set:
        return {}

    tool, action, scope = mapping
    project_id = detect_project_id()
    pkey = _pending_key(payload.session_id, payload.tool_name, payload.tool_input)
    display_scope = _short_scope(scope)

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
        project_id=project_id,
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
            project_id=project_id,
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
        with _auto_approved_lock:
            if len(_auto_approved) >= _MAX_AUTO_APPROVED:
                _auto_approved.clear()
            _auto_approved.add(pkey)
        return {
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {
                    "behavior": "allow",
                    "message": f"AIperture auto-approved {payload.tool_name}({display_scope})",
                },
                "additionalContext": (
                    f"AIperture auto-approved this action based on learned patterns. "
                    f"Tool: {payload.tool_name}, scope: {display_scope}. "
                    f"Decided by: {verdict.decided_by}."
                ),
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
                    "message": (
                        f"AIperture auto-denied {payload.tool_name}({display_scope}). "
                        f"This pattern has been consistently denied in past decisions."
                    ),
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
        project_id=project_id,
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

    Returns learning progress so Claude can relay milestones to the user.
    """
    from aiperture.config import settings
    from aiperture.metrics import HOOK_POST_TOOL_USE

    # Map Claude Code tool to AIperture triple
    mapping = map_tool(payload.tool_name, payload.tool_input)
    if mapping is None:
        return {"recorded": False, "reason": "skipped"}

    # Skip tools that Claude Code auto-allows (no human decision involved)
    if payload.tool_name in settings.hook_auto_allowed_tools_set:
        return {"recorded": False, "reason": "hook_auto_allowed"}

    tool, action, scope = mapping
    HOOK_POST_TOOL_USE.inc()

    pkey = _pending_key(payload.session_id, payload.tool_name, payload.tool_input)

    # Skip recording if this was auto-approved by AIperture
    with _auto_approved_lock:
        if pkey in _auto_approved:
            _auto_approved.discard(pkey)
            return {"recorded": False, "reason": "auto_approved"}

    # Resolve pending request — returns True only if PermissionRequest was seen,
    # meaning Claude Code actually showed the user a permission prompt.
    was_pending = pending.resolve(pkey)

    if not was_pending:
        # No PermissionRequest was seen — Claude Code auto-allowed this via its
        # own permission settings. Not a human decision, so don't learn from it.
        return {"recorded": False, "reason": "no_permission_prompt"}

    # Record implicit approval in background for speed
    project_id = detect_project_id()
    background_tasks.add_task(
        _record_implicit_approval,
        tool=tool,
        action=action,
        scope=scope,
        session_id=payload.session_id,
        project_id=project_id,
    )

    # Compute learning progress (synchronous — fast, single DB query)
    display_scope = _short_scope(scope)
    progress = _learning_progress(tool, action, scope, "default", project_id)

    if progress and progress["status"] == "auto_approve":
        # Just reached auto-approve threshold!
        return {
            "recorded": True,
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": (
                    f"AIperture milestone: {payload.tool_name}({display_scope}) "
                    f"will now be auto-approved! "
                    f"{progress['current_count']} decisions at {progress['approval_rate']:.0%} approval rate. "
                    f"Future uses will skip the permission prompt."
                ),
            },
        }

    if progress and progress["status"] == "learning":
        return {
            "recorded": True,
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": (
                    f"AIperture learned: approval recorded for {payload.tool_name}({display_scope}). "
                    f"{progress['message']}"
                ),
            },
        }

    if progress and progress["status"] == "new":
        return {
            "recorded": True,
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": (
                    f"AIperture: first approval recorded for {payload.tool_name}({display_scope}). "
                    f"{progress['message']}"
                ),
            },
        }

    return {"recorded": True}


def _record_implicit_approval(
    tool: str,
    action: str,
    scope: str,
    session_id: str,
    project_id: str = "global",
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
            project_id=project_id,
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
                project_id=req.project_id,
                runtime_id="claude-code",
            )
        except Exception:
            logger.error(
                "Failed to record inferred denial for %s.%s on %s",
                req.tool, req.action, req.scope, exc_info=True,
            )
