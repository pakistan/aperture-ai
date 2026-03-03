"""Permission engine — glob-based RBAC with task-scoped ReBAC overrides.

Zero LLM cost. All decisions are deterministic pattern matching.

Resolution order:
1. Session memory — if already decided this session, reuse
2. Task-scoped grants (ReBAC) — if active, use that decision
3. Learned auto-decisions — if pattern is strong enough
4. Static permission rules — glob match with specificity ranking
5. Default deny

When enrich=True, the engine also computes:
- Risk classification
- Command explanation
- Crowd signal from org history
- Similar patterns
- Cross-org intelligence
- Actionable recommendations
"""

import fnmatch
import logging
import threading
import uuid
from collections import OrderedDict
from datetime import UTC, datetime, timedelta

_MAX_SESSION_CACHE_SIZE = 10_000

from sqlmodel import Session, select

from aperture.db import get_engine
from aperture.models.permission import (
    Permission,
    PermissionDecision,
    PermissionLog,
    TaskPermission,
    TaskPermissionStatus,
)
from aperture.models.verdict import PermissionVerdict, RiskAssessment, RiskTier

logger = logging.getLogger(__name__)


class PermissionEngine:
    """Deterministic permission checker for AI agent actions."""

    def __init__(self, max_cache_size: int = _MAX_SESSION_CACHE_SIZE):
        # Cache key: (organization_id, tool, action, scope, session_id, content_hash)
        self._session_cache: OrderedDict[tuple[str, str, str, str, str, str], PermissionDecision] = OrderedDict()
        self._max_cache_size = max_cache_size
        self._cache_lock = threading.Lock()

    def check(
        self,
        tool: str,
        action: str,
        scope: str,
        permissions: list[Permission],
        *,
        task_id: str = "",
        session_id: str = "",
        organization_id: str = "default",
        runtime_id: str = "",
        enrich: bool = False,
        content_hash: str = "",
    ) -> PermissionVerdict:
        """Check if an action is permitted. Returns enriched verdict.

        Args:
            tool: Tool name (e.g., "filesystem", "shell", "api")
            action: Action name (e.g., "read", "write", "execute")
            scope: Resource scope (e.g., "src/*.py", "production.database")
            permissions: Static permission rules for this agent/context
            task_id: If set, check task-scoped ReBAC grants first
            session_id: Session identifier for grouping and memory
            organization_id: Tenant ID
            runtime_id: Which external runtime is asking
            enrich: If True, compute risk, explanation, crowd signal, etc.
            content_hash: Optional content hash — different hashes = different checks

        Returns:
            PermissionVerdict with decision and optional enrichment.
        """
        # 0. Session memory (organization_id + content_hash are part of the cache key)
        cache_key = (organization_id, tool, action, scope, session_id, content_hash)
        if session_id:
            with self._cache_lock:
                cached = self._session_cache.get(cache_key)
            if cached is not None:
                verdict = self._build_verdict(
                    cached, "session_memory", tool, action, scope,
                    organization_id=organization_id, enrich=enrich,
                    content_hash=content_hash, session_id=session_id,
                )
                self._log(
                    tool, action, scope, cached, "session_memory",
                    task_id=task_id, session_id=session_id,
                    organization_id=organization_id, runtime_id=runtime_id,
                )
                return verdict

        # 1. Check task-scoped grants (ReBAC)
        if task_id:
            task_decision = self._check_task_permissions(
                tool, action, scope, task_id, organization_id
            )
            if task_decision is not None:
                self._log(
                    tool, action, scope, task_decision, "rebac",
                    task_id=task_id, session_id=session_id,
                    organization_id=organization_id, runtime_id=runtime_id,
                )
                return self._build_verdict(
                    task_decision, "rebac", tool, action, scope,
                    organization_id=organization_id, enrich=enrich,
                    session_id=session_id,
                )

        # 2. Check learned auto-decisions
        learned = self._check_learned(tool, action, scope, organization_id)
        if learned is not None:
            self._log(
                tool, action, scope, learned, "auto_learned",
                task_id=task_id, session_id=session_id,
                organization_id=organization_id, runtime_id=runtime_id,
            )
            return self._build_verdict(
                learned, "auto_learned", tool, action, scope,
                organization_id=organization_id, enrich=enrich,
                session_id=session_id,
            )

        # 3. Static permission rules — glob match with specificity
        decision = self._match_static(tool, action, scope, permissions)

        self._log(
            tool, action, scope, decision, "static_rule",
            task_id=task_id, session_id=session_id,
            organization_id=organization_id, runtime_id=runtime_id,
        )
        return self._build_verdict(
            decision, "static_rule", tool, action, scope,
            organization_id=organization_id, enrich=enrich,
            session_id=session_id,
        )

    def grant_task_permission(
        self,
        task_id: str,
        tool: str,
        action: str,
        scope: str,
        decision: PermissionDecision,
        granted_by: str,
        organization_id: str = "default",
        ttl_seconds: int | None = None,
    ) -> TaskPermission:
        """Grant a task-scoped permission (ReBAC)."""
        expires_at = None
        if ttl_seconds:
            expires_at = datetime.now(UTC).replace(tzinfo=None) + timedelta(seconds=ttl_seconds)

        grant = TaskPermission(
            permission_id=uuid.uuid4().hex[:16],
            task_id=task_id,
            organization_id=organization_id,
            tool=tool,
            action=action,
            scope=scope,
            decision=decision.value,
            status=TaskPermissionStatus.ACTIVE,
            granted_by=granted_by,
            expires_at=expires_at,
        )
        with Session(get_engine()) as session:
            session.add(grant)
            session.commit()
            session.refresh(grant)
            session.expunge(grant)
        return grant

    def record_human_decision(
        self,
        tool: str,
        action: str,
        scope: str,
        decision: PermissionDecision,
        decided_by: str,
        *,
        challenge: str = "",
        challenge_nonce: str = "",
        challenge_issued_at: float = 0.0,
        task_id: str = "",
        session_id: str = "",
        organization_id: str = "default",
        runtime_id: str = "",
        reasoning: str = "",
    ) -> PermissionLog:
        """Record a human's permission decision for learning.

        Requires a valid HMAC challenge token from the original check_permission
        verdict. This prevents agents from fabricating approvals without human
        involvement.

        Also caches in session memory so the same check in the same session
        returns the same decision without re-asking.
        """
        from aperture.permissions.challenge import verify_challenge

        if not verify_challenge(
            token=challenge,
            nonce=challenge_nonce,
            issued_at=challenge_issued_at,
            tool=tool,
            action=action,
            scope=scope,
            organization_id=organization_id,
            session_id=session_id,
        ):
            logger.warning(
                "Rejected human decision without valid challenge: %s.%s on %s by %s",
                tool, action, scope, decided_by,
            )
            raise ValueError(
                "Invalid or missing challenge token. "
                "Human decisions must include the challenge from the original permission check."
            )
        # Cache in session memory (LRU eviction at max size)
        if session_id:
            cache_key = (organization_id, tool, action, scope, session_id, "")
            with self._cache_lock:
                self._session_cache[cache_key] = decision
                self._session_cache.move_to_end(cache_key)
                while len(self._session_cache) > self._max_cache_size:
                    self._session_cache.popitem(last=False)

        return self._log(
            tool, action, scope, decision, f"human:{decided_by}",
            task_id=task_id, session_id=session_id,
            organization_id=organization_id, runtime_id=runtime_id,
        )

    def revoke_pattern(
        self,
        tool: str,
        action: str,
        scope: str,
        revoked_by: str,
        organization_id: str = "default",
    ) -> int:
        """Revoke all learned decisions matching (tool, action, scope).

        Soft-deletes by setting revoked_at. Preserves audit trail.

        Returns:
            Number of decisions revoked.
        """
        now = datetime.now(UTC).replace(tzinfo=None)
        count = 0

        with Session(get_engine()) as session:
            logs = session.exec(
                select(PermissionLog).where(
                    PermissionLog.organization_id == organization_id,
                    PermissionLog.tool == tool,
                    PermissionLog.action == action,
                    PermissionLog.decided_by.startswith("human:"),  # type: ignore[union-attr]
                    PermissionLog.revoked_at.is_(None),  # type: ignore[union-attr]
                )
            ).all()

            for log in logs:
                if fnmatch.fnmatch(log.scope, scope) or log.scope == scope:
                    log.revoked_at = now
                    session.add(log)
                    count += 1

            session.commit()

        # Clear session cache entries for this pattern
        with self._cache_lock:
            to_remove = [
                k for k in self._session_cache
                if k[1] == tool and k[2] == action and (fnmatch.fnmatch(k[3], scope) or k[3] == scope)
            ]
            for k in to_remove:
                del self._session_cache[k]

        return count

    # --- Internal methods ---

    def _build_verdict(
        self,
        decision: PermissionDecision,
        decided_by: str,
        tool: str,
        action: str,
        scope: str,
        *,
        organization_id: str = "default",
        enrich: bool = False,
        content_hash: str = "",
        session_id: str = "",
    ) -> PermissionVerdict:
        """Build a PermissionVerdict, optionally enriched with signals."""
        from aperture.permissions.challenge import create_challenge
        from aperture.permissions.risk import classify_risk

        # Risk is always computed (it's cheap — pure function)
        risk = classify_risk(tool, action, scope)

        # Content change detection: check if same (tool, action, scope) was seen
        # with a different content_hash in the same session
        content_changed = False
        if content_hash and session_id:
            with self._cache_lock:
                for cached_key in self._session_cache:
                    if (
                        cached_key[0] == organization_id
                        and cached_key[1] == tool
                        and cached_key[2] == action
                        and cached_key[3] == scope
                        and cached_key[4] == session_id
                        and cached_key[5]
                        and cached_key[5] != content_hash
                    ):
                        content_changed = True
                        break

        # Generate HMAC challenge for non-ALLOW decisions
        challenge_token = None
        if decision != PermissionDecision.ALLOW:
            challenge_token = create_challenge(
                tool, action, scope,
                organization_id=organization_id,
                session_id=session_id,
            )

        if not enrich:
            verdict = PermissionVerdict(
                decision=decision,
                decided_by=decided_by,
                risk=risk,
                content_changed=content_changed,
            )
            if challenge_token:
                verdict.challenge = challenge_token.token
                verdict.challenge_nonce = challenge_token.nonce
                verdict.challenge_issued_at = challenge_token.issued_at
            return verdict

        # Full enrichment
        from aperture.permissions.crowd import compute_auto_approve_distance, get_org_signal
        from aperture.permissions.explainer import explain_action
        from aperture.permissions.similarity import find_similar_patterns

        explanation = explain_action(tool, action, scope, risk)
        org_signal = get_org_signal(tool, action, scope, organization_id)

        similar = find_similar_patterns(
            tool, action, scope, organization_id,
            min_similarity=0.5, limit=5,
        )

        # Auto-approve distance
        auto_distance = None
        if org_signal:
            import aperture.config
            auto_distance = compute_auto_approve_distance(
                org_signal,
                aperture.config.settings.permission_learning_min_decisions,
                aperture.config.settings.auto_approve_threshold,
            )

        # Cross-org intelligence (if enabled)
        global_signal = None
        try:
            import aperture.config
            if aperture.config.settings.intelligence_enabled:
                from aperture.permissions.intelligence import IntelligenceEngine
                intel = IntelligenceEngine(
                    min_orgs=aperture.config.settings.intelligence_min_orgs,
                    default_epsilon=aperture.config.settings.intelligence_epsilon,
                )
                global_signal = intel.get_global_signal(tool, action, scope)
        except Exception:
            logger.debug("Intelligence unavailable", exc_info=True)

        # Recommendation
        rec_code, rec_text = self._compute_recommendation(
            decision, org_signal, similar, risk,
        )

        verdict = PermissionVerdict(
            decision=decision,
            decided_by=decided_by,
            risk=risk,
            explanation=explanation,
            org_signal=org_signal,
            similar_patterns=similar,
            global_signal=global_signal,
            auto_approve_distance=auto_distance,
            recommendation=rec_text,
            recommendation_code=rec_code,
            content_changed=content_changed,
        )
        if challenge_token:
            verdict.challenge = challenge_token.token
            verdict.challenge_nonce = challenge_token.nonce
            verdict.challenge_issued_at = challenge_token.issued_at
        return verdict

    def _compute_recommendation(
        self,
        decision: PermissionDecision,
        org_signal,
        similar: list,
        risk: RiskAssessment,
    ) -> tuple[str, str]:
        """Compute recommendation based on all signals."""
        if org_signal:
            if org_signal.allow_rate >= 0.95 and org_signal.total_decisions >= 10:
                return (
                    "auto_approve",
                    f"Strong approve — {org_signal.allow_rate:.0%} rate, "
                    f"{org_signal.total_decisions} decisions, "
                    f"{org_signal.unique_humans} reviewer(s).",
                )
            if org_signal.allow_rate <= 0.05 and org_signal.total_decisions >= 10:
                return (
                    "auto_deny",
                    f"Strong deny — {org_signal.allow_rate:.0%} rate, "
                    f"{org_signal.total_decisions} decisions.",
                )
            if org_signal.total_decisions >= 10 and 0.85 <= org_signal.allow_rate < 0.95:
                return (
                    "suggest_rule",
                    f"Approved {org_signal.allow_rate:.0%} of the time across "
                    f"{org_signal.total_decisions} decisions. Consider a permanent allow rule.",
                )
            if 0.3 <= org_signal.allow_rate <= 0.7:
                return (
                    "review",
                    f"Split decisions ({org_signal.allow_rate:.0%}). Needs human judgment.",
                )

        if risk.tier == RiskTier.CRITICAL:
            return ("caution", "CRITICAL risk. Review carefully before approving.")

        if similar:
            best = similar[0]
            return (
                "keep_asking",
                f"No exact history. Most similar: {best.tool}.{best.action} on {best.scope} "
                f"({best.allow_rate:.0%} approved, {best.total_decisions} decisions).",
            )

        return ("caution", "New pattern — no prior decisions. Proceed carefully.")

    def _match_static(
        self,
        tool: str,
        action: str,
        scope: str,
        permissions: list[Permission],
    ) -> PermissionDecision:
        """Match against static rules. Most specific match wins."""
        best_match: Permission | None = None
        best_specificity = -1

        for perm in permissions:
            if not fnmatch.fnmatch(tool, perm.tool):
                continue
            if not fnmatch.fnmatch(action, perm.action):
                continue
            if not fnmatch.fnmatch(scope, perm.scope):
                continue

            specificity = len(perm.scope) - perm.scope.count("*") - perm.scope.count("?")
            if specificity > best_specificity:
                best_specificity = specificity
                best_match = perm

        if best_match is None:
            return PermissionDecision.DENY

        return best_match.decision

    def _check_task_permissions(
        self,
        tool: str,
        action: str,
        scope: str,
        task_id: str,
        organization_id: str,
    ) -> PermissionDecision | None:
        """Check task-scoped ReBAC grants."""
        now = datetime.now(UTC).replace(tzinfo=None)
        with Session(get_engine()) as session:
            grants = session.exec(
                select(TaskPermission).where(
                    TaskPermission.task_id == task_id,
                    TaskPermission.organization_id == organization_id,
                    TaskPermission.status == TaskPermissionStatus.ACTIVE,
                )
            ).all()

        for grant in grants:
            if grant.expires_at and grant.expires_at < now:
                continue
            if not fnmatch.fnmatch(tool, grant.tool):
                continue
            if not fnmatch.fnmatch(action, grant.action):
                continue
            if not fnmatch.fnmatch(scope, grant.scope):
                continue
            return PermissionDecision(grant.decision)

        return None

    def _check_learned(
        self,
        tool: str,
        action: str,
        scope: str,
        organization_id: str,
    ) -> PermissionDecision | None:
        """Check if we've learned enough to auto-decide.

        HIGH and CRITICAL risk actions are never auto-approved — they always
        require explicit human approval regardless of history. This prevents
        a user approving `rm -rf ./build/` a few times from causing Aperture
        to auto-approve destructive commands.
        """
        import aperture.config

        settings = aperture.config.settings
        if not settings.permission_learning_enabled:
            return None

        # Never auto-approve HIGH or CRITICAL risk actions
        from aperture.permissions.risk import classify_risk

        risk = classify_risk(tool, action, scope)
        if risk.tier in (RiskTier.HIGH, RiskTier.CRITICAL):
            logger.debug(
                "Skipping auto-learn for %s.%s on %s — risk tier is %s",
                tool, action, scope, risk.tier.value,
            )
            return None

        with Session(get_engine()) as session:
            logs = session.exec(
                select(PermissionLog).where(
                    PermissionLog.organization_id == organization_id,
                    PermissionLog.tool == tool,
                    PermissionLog.action == action,
                    PermissionLog.decided_by.startswith("human:"),  # type: ignore[union-attr]
                    PermissionLog.revoked_at.is_(None),  # type: ignore[union-attr]  # exclude revoked
                ).order_by(PermissionLog.created_at.desc())  # type: ignore[union-attr]
            ).all()

        if not logs:
            return None

        matching = [log for log in logs if fnmatch.fnmatch(scope, log.scope)]

        if len(matching) < settings.permission_learning_min_decisions:
            return None

        allow_count = sum(1 for log in matching if log.decision == PermissionDecision.ALLOW)
        rate = allow_count / len(matching)

        if rate >= settings.auto_approve_threshold:
            logger.info(
                "Auto-approving %s.%s on %s (%.0f%% approval rate, %d decisions)",
                tool, action, scope, rate * 100, len(matching),
            )
            return PermissionDecision.ALLOW

        if rate <= settings.auto_deny_threshold:
            logger.info(
                "Auto-denying %s.%s on %s (%.0f%% approval rate, %d decisions)",
                tool, action, scope, rate * 100, len(matching),
            )
            return PermissionDecision.DENY

        return None

    def _log(
        self,
        tool: str,
        action: str,
        scope: str,
        decision: PermissionDecision,
        decided_by: str,
        *,
        task_id: str = "",
        session_id: str = "",
        organization_id: str = "default",
        runtime_id: str = "",
    ) -> PermissionLog:
        """Persist every permission decision. Fire-and-forget."""
        from aperture.permissions.resource import extract_resource

        resource = extract_resource(tool, action, scope)

        log_entry = PermissionLog(
            organization_id=organization_id,
            task_id=task_id,
            session_id=session_id,
            tool=tool,
            action=action,
            scope=scope,
            resource=resource,
            decision=decision.value,
            decided_by=decided_by,
            runtime_id=runtime_id,
        )
        try:
            with Session(get_engine()) as session:
                session.add(log_entry)
                session.commit()
                session.refresh(log_entry)
                session.expunge(log_entry)
        except Exception:
            logger.error("Failed to log permission decision for %s.%s", tool, action, exc_info=True)
        return log_entry
