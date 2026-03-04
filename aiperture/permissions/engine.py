"""Permission engine — glob-based RBAC with task-scoped ReBAC overrides.

Zero LLM cost. All decisions are deterministic pattern matching.

Resolution order:
1. Session memory — if already decided this session, reuse
2. Task-scoped grants (ReBAC) — if active, use that decision
3. Learned auto-decisions — if pattern is strong enough
4. Static permission rules — glob match with specificity ranking
5. Default decision (configurable, default: ask)

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
import time
import uuid
from collections import OrderedDict
from datetime import UTC, datetime, timedelta

_MAX_SESSION_CACHE_SIZE = 10_000

from sqlmodel import Session, select

from aiperture.db import get_engine
from aiperture.models.permission import (
    Permission,
    PermissionDecision,
    PermissionLog,
    TaskPermission,
    TaskPermissionStatus,
)
from aiperture.models.verdict import PermissionVerdict, RiskAssessment, RiskTier

logger = logging.getLogger(__name__)


class _DefaultSessionCache:
    """In-memory LRU session cache (default implementation)."""

    def __init__(self, max_size: int = _MAX_SESSION_CACHE_SIZE):
        self._data: OrderedDict = OrderedDict()
        self._max_size = max_size
        self._lock = threading.Lock()

    def get(self, key: tuple):
        with self._lock:
            return self._data.get(key)

    def set(self, key: tuple, value) -> None:
        with self._lock:
            self._data[key] = value
            self._data.move_to_end(key)
            while len(self._data) > self._max_size:
                self._data.popitem(last=False)

    def delete(self, key: tuple) -> None:
        with self._lock:
            self._data.pop(key, None)

    def delete_matching(self, predicate) -> int:
        with self._lock:
            to_remove = [k for k in self._data if predicate(k)]
            for k in to_remove:
                del self._data[k]
            return len(to_remove)

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)


class PermissionEngine:
    """Deterministic permission checker for AI agent actions."""

    def __init__(self, max_cache_size: int = _MAX_SESSION_CACHE_SIZE):
        from aiperture import plugins

        plugin_cache = plugins.get("session_cache")
        if plugin_cache is not None:
            self._session_cache = plugin_cache
        else:
            self._session_cache = _DefaultSessionCache(max_cache_size)

        # Rubber-stamping tracker: key → list of timestamps
        self._rapid_approval_tracker: dict[str, list[float]] = {}
        self._rapid_lock = threading.Lock()

        # Rate limiter: (session_id, org_id) → list of timestamps
        self._rate_tracker: dict[str, list[float]] = {}
        self._rate_lock = threading.Lock()

        # Session risk budget: session_id → cumulative risk score
        self._session_risk_budget: dict[str, float] = {}
        self._risk_budget_lock = threading.Lock()

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
        from aiperture.metrics import (
            PERMISSION_CHECKS, RATE_LIMITED, SESSION_CACHE_HITS,
            SESSION_CACHE_MISSES, AUTO_APPROVED, AUTO_DENIED,
            RISK_BUDGET_EXHAUSTED, track_check_duration,
        )

        with track_check_duration():
            return self._check_inner(
                tool, action, scope, permissions,
                task_id=task_id, session_id=session_id,
                organization_id=organization_id, runtime_id=runtime_id,
                enrich=enrich, content_hash=content_hash,
            )

    def _check_inner(
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
        from aiperture.metrics import (
            PERMISSION_CHECKS, RATE_LIMITED, SESSION_CACHE_HITS,
            SESSION_CACHE_MISSES, AUTO_APPROVED, AUTO_DENIED,
            RISK_BUDGET_EXHAUSTED,
        )

        # Rate limiting: deny if session exceeds checks/minute
        if session_id:
            rate_verdict = self._check_rate_limit(session_id, organization_id, tool, action, scope, enrich)
            if rate_verdict is not None:
                RATE_LIMITED.inc()
                PERMISSION_CHECKS.labels(decision="deny", decided_by="rate_limit").inc()
                self._log(
                    tool, action, scope, PermissionDecision.DENY, "rate_limit",
                    task_id=task_id, session_id=session_id,
                    organization_id=organization_id, runtime_id=runtime_id,
                )
                logger.warning("DENY %s/%s %s (rate_limit)", tool, action, scope)
                return rate_verdict

        # 0. Session memory (organization_id + content_hash are part of the cache key)
        cache_key = (organization_id, tool, action, scope, session_id, content_hash)
        if session_id:
            cached = self._session_cache.get(cache_key)
            if cached is not None:
                SESSION_CACHE_HITS.inc()
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
                logger.debug("%s %s/%s %s (session_memory)", cached.value.upper(), tool, action, scope)
                return verdict

        if session_id:
            SESSION_CACHE_MISSES.inc()

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
                self._log_decision(task_decision, tool, action, scope, "rebac")
                return self._build_verdict(
                    task_decision, "rebac", tool, action, scope,
                    organization_id=organization_id, enrich=enrich,
                    session_id=session_id,
                )

        # 2. Check learned auto-decisions
        learned = self._check_learned(tool, action, scope, organization_id)
        if learned is not None:
            # Session risk budget: escalate ALLOW to ASK if budget exhausted
            if learned == PermissionDecision.ALLOW and session_id:
                original = learned
                learned = self._apply_risk_budget(session_id, tool, action, scope, learned)
                if learned != original:
                    RISK_BUDGET_EXHAUSTED.inc()
            if learned == PermissionDecision.ALLOW:
                AUTO_APPROVED.inc()
            elif learned == PermissionDecision.DENY:
                AUTO_DENIED.inc()
            PERMISSION_CHECKS.labels(decision=learned.value, decided_by="auto_learned").inc()
            self._log(
                tool, action, scope, learned, "auto_learned",
                task_id=task_id, session_id=session_id,
                organization_id=organization_id, runtime_id=runtime_id,
            )
            self._log_decision(learned, tool, action, scope, "auto_learned")
            return self._build_verdict(
                learned, "auto_learned", tool, action, scope,
                organization_id=organization_id, enrich=enrich,
                session_id=session_id,
            )

        # 3. Static permission rules — glob match with specificity
        static_decision = self._match_static(tool, action, scope, permissions)

        if static_decision is not None:
            # Session risk budget: escalate ALLOW to ASK if budget exhausted
            if static_decision == PermissionDecision.ALLOW and session_id:
                original = static_decision
                static_decision = self._apply_risk_budget(session_id, tool, action, scope, static_decision)
                if static_decision != original:
                    RISK_BUDGET_EXHAUSTED.inc()

            PERMISSION_CHECKS.labels(decision=static_decision.value, decided_by="static_rule").inc()
            self._log(
                tool, action, scope, static_decision, "static_rule",
                task_id=task_id, session_id=session_id,
                organization_id=organization_id, runtime_id=runtime_id,
            )
            self._log_decision(static_decision, tool, action, scope, "static_rule")
            return self._build_verdict(
                static_decision, "static_rule", tool, action, scope,
                organization_id=organization_id, enrich=enrich,
                session_id=session_id,
            )

        # 4. Default decision (configurable, default: ask)
        import aiperture.config
        decision = PermissionDecision(aiperture.config.settings.default_decision)
        PERMISSION_CHECKS.labels(decision=decision.value, decided_by="default").inc()
        self._log(
            tool, action, scope, decision, "default",
            task_id=task_id, session_id=session_id,
            organization_id=organization_id, runtime_id=runtime_id,
        )
        self._log_decision(decision, tool, action, scope, "default")
        return self._build_verdict(
            decision, "default", tool, action, scope,
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
        from aiperture.permissions.challenge import verify_challenge

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
        # Rubber-stamping detection: flag rapid approvals (requires session context)
        effective_decided_by = f"human:{decided_by}"
        if decision == PermissionDecision.ALLOW and session_id:
            effective_decided_by = self._check_rapid_approval(
                session_id, tool, action, decided_by,
            )

        # Cache in session memory
        if session_id:
            cache_key = (organization_id, tool, action, scope, session_id, "")
            self._session_cache.set(cache_key, decision)

        return self._log(
            tool, action, scope, decision, effective_decided_by,
            task_id=task_id, session_id=session_id,
            organization_id=organization_id, runtime_id=runtime_id,
        )

    def record_hook_decision(
        self,
        tool: str,
        action: str,
        scope: str,
        decision: PermissionDecision,
        *,
        session_id: str = "",
        organization_id: str = "default",
        runtime_id: str = "",
    ) -> PermissionLog:
        """Record a permission decision from Claude Code's hook integration.

        Unlike record_human_decision, this does NOT require an HMAC challenge
        token. Claude Code's own permission dialog is the human verification
        gate — if PostToolUse fires, the user approved.

        Records with decided_by="human:claude-code-hook" so the learning
        engine picks up the "human:" prefix and includes it in pattern
        detection.
        """
        # Rubber-stamping detection
        effective_decided_by = "human:claude-code-hook"
        if decision == PermissionDecision.ALLOW and session_id:
            effective_decided_by = self._check_rapid_approval(
                session_id, tool, action, "claude-code-hook",
            )

        # Cache in session memory
        if session_id:
            cache_key = (organization_id, tool, action, scope, session_id, "")
            self._session_cache.set(cache_key, decision)

        # Also record with normalized scope to accelerate learning
        from aiperture.permissions.scope_normalize import normalize_scope

        normalized = normalize_scope(tool, action, scope)
        if normalized and normalized != scope:
            norm_cache_key = (organization_id, tool, action, normalized, session_id, "")
            self._session_cache.set(norm_cache_key, decision)
            self._log(
                tool, action, normalized, decision, effective_decided_by,
                session_id=session_id,
                organization_id=organization_id, runtime_id=runtime_id,
            )

        return self._log(
            tool, action, scope, decision, effective_decided_by,
            session_id=session_id,
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
        self._session_cache.delete_matching(
            lambda k: k[1] == tool and k[2] == action and (fnmatch.fnmatch(k[3], scope) or k[3] == scope)
        )

        return count

    # --- Internal methods ---

    @staticmethod
    def _log_decision(
        decision: PermissionDecision,
        tool: str,
        action: str,
        scope: str,
        decided_by: str,
    ) -> None:
        """Log permission decisions to stderr for developer visibility.

        DENY → WARNING, ASK → INFO, ALLOW → DEBUG.
        """
        label = decision.value.upper()
        msg = "%s %s/%s %s (%s)"
        args = (label, tool, action, scope, decided_by)
        if decision == PermissionDecision.DENY:
            logger.warning(msg, *args)
        elif decision == PermissionDecision.ASK:
            logger.info(msg, *args)
        else:
            logger.debug(msg, *args)

    def _check_rapid_approval(
        self,
        session_id: str,
        tool: str,
        action: str,
        decided_by: str,
    ) -> str:
        """Detect rubber-stamping: rapid approvals for the same pattern.

        Returns the decided_by string, with `:rapid` suffix if flagged.
        """
        import aiperture.config

        settings = aiperture.config.settings
        window = settings.rapid_approval_window_seconds
        min_count = settings.rapid_approval_min_count

        tracker_key = f"{session_id}:{tool}:{action}"
        now = time.time()

        with self._rapid_lock:
            timestamps = self._rapid_approval_tracker.get(tracker_key, [])
            # Prune timestamps outside the window
            timestamps = [t for t in timestamps if now - t <= window]
            timestamps.append(now)
            self._rapid_approval_tracker[tracker_key] = timestamps

            if len(timestamps) >= min_count:
                logger.warning(
                    "Rubber-stamping detected: %d approvals for %s.%s in %ds by %s",
                    len(timestamps), tool, action, window, decided_by,
                )
                return f"human:{decided_by}:rapid"

        return f"human:{decided_by}"

    def _check_rate_limit(
        self,
        session_id: str,
        organization_id: str,
        tool: str,
        action: str,
        scope: str,
        enrich: bool,
    ) -> PermissionVerdict | None:
        """Check per-session rate limit. Returns DENY verdict if exceeded."""
        import aiperture.config

        limit = aiperture.config.settings.rate_limit_per_minute
        if limit <= 0:
            return None  # Unlimited

        tracker_key = f"{session_id}:{organization_id}"
        now = time.time()
        window = 60.0  # 1 minute

        with self._rate_lock:
            timestamps = self._rate_tracker.get(tracker_key, [])
            timestamps = [t for t in timestamps if now - t <= window]
            timestamps.append(now)
            self._rate_tracker[tracker_key] = timestamps

            if len(timestamps) > limit:
                logger.warning(
                    "Rate limit exceeded: %d checks/min for session %s (limit %d)",
                    len(timestamps), session_id, limit,
                )
                return PermissionVerdict(
                    decision=PermissionDecision.DENY,
                    decided_by="rate_limit",
                    risk=RiskAssessment(tier=RiskTier.MEDIUM, score=0.5, factors=["rate_limit_exceeded"]),
                )

        return None

    _RISK_SCORE_MAP = {
        RiskTier.LOW: 0.1,
        RiskTier.MEDIUM: 0.3,
        RiskTier.HIGH: 0.7,
        RiskTier.CRITICAL: 1.0,
    }

    def _apply_risk_budget(
        self,
        session_id: str,
        tool: str,
        action: str,
        scope: str,
        decision: PermissionDecision,
    ) -> PermissionDecision:
        """Accumulate session risk and escalate to ASK if budget exhausted."""
        import aiperture.config
        from aiperture.permissions.risk import classify_risk

        budget_limit = aiperture.config.settings.session_risk_budget
        if budget_limit <= 0:
            return decision  # Disabled

        risk = classify_risk(tool, action, scope)
        score = self._RISK_SCORE_MAP.get(risk.tier, 0.1)

        with self._risk_budget_lock:
            current = self._session_risk_budget.get(session_id, 0.0)
            current += score
            self._session_risk_budget[session_id] = current

            if current > budget_limit:
                logger.warning(
                    "Session risk budget exhausted for %s (%.1f/%.1f) — escalating %s.%s to ASK",
                    session_id, current, budget_limit, tool, action,
                )
                return PermissionDecision.ASK

        return decision

    def get_session_risk_budget(self, session_id: str) -> float:
        """Return remaining risk budget for a session."""
        import aiperture.config

        budget_limit = aiperture.config.settings.session_risk_budget
        with self._risk_budget_lock:
            used = self._session_risk_budget.get(session_id, 0.0)
        return max(0.0, budget_limit - used)

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
        from aiperture.permissions.challenge import create_challenge
        from aiperture.permissions.risk import classify_risk

        # Risk is always computed (it's cheap — pure function)
        risk = classify_risk(tool, action, scope)

        # Content change detection: check if same (tool, action, scope) was seen
        # with a different content_hash in the same session.
        # We probe the cache for the empty-hash key (set by record_human_decision)
        # — if a decision exists with no content_hash, the content has changed.
        content_changed = False
        if content_hash and session_id:
            empty_hash_key = (organization_id, tool, action, scope, session_id, "")
            prev = self._session_cache.get(empty_hash_key)
            if prev is not None:
                content_changed = True

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
        from aiperture.permissions.crowd import compute_auto_approve_distance, get_org_signal
        from aiperture.permissions.explainer import explain_action
        from aiperture.permissions.similarity import find_similar_patterns

        explanation = explain_action(tool, action, scope, risk)
        org_signal = get_org_signal(tool, action, scope, organization_id)

        similar = find_similar_patterns(
            tool, action, scope, organization_id,
            min_similarity=0.5, limit=5,
        )

        # Auto-approve distance
        auto_distance = None
        if org_signal:
            import aiperture.config
            auto_distance = compute_auto_approve_distance(
                org_signal,
                aiperture.config.settings.permission_learning_min_decisions,
                aiperture.config.settings.auto_approve_threshold,
            )

        # Cross-org intelligence (if enabled)
        global_signal = None
        try:
            import aiperture.config
            if aiperture.config.settings.intelligence_enabled:
                from aiperture.permissions.intelligence import IntelligenceEngine
                intel = IntelligenceEngine(
                    min_orgs=aiperture.config.settings.intelligence_min_orgs,
                    default_epsilon=aiperture.config.settings.intelligence_epsilon,
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
        import aiperture.config
        approve_threshold = aiperture.config.settings.auto_approve_threshold
        deny_threshold = aiperture.config.settings.auto_deny_threshold
        min_decisions = aiperture.config.settings.permission_learning_min_decisions

        if org_signal:
            if org_signal.allow_rate >= approve_threshold and org_signal.total_decisions >= min_decisions:
                return (
                    "auto_approve",
                    f"Strong approve — {org_signal.allow_rate:.0%} rate, "
                    f"{org_signal.total_decisions} decisions, "
                    f"{org_signal.unique_humans} reviewer(s).",
                )
            if org_signal.allow_rate <= deny_threshold and org_signal.total_decisions >= min_decisions:
                return (
                    "auto_deny",
                    f"Strong deny — {org_signal.allow_rate:.0%} rate, "
                    f"{org_signal.total_decisions} decisions.",
                )
            if org_signal.total_decisions >= min_decisions and 0.85 <= org_signal.allow_rate < approve_threshold:
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
    ) -> PermissionDecision | None:
        """Match against static rules. Most specific match wins.

        Returns None if no static rule matches (caller applies default decision).
        """
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
            return None

        return best_match.decision

    def _check_task_permissions(
        self,
        tool: str,
        action: str,
        scope: str,
        task_id: str,
        organization_id: str,
    ) -> PermissionDecision | None:
        """Check task-scoped ReBAC grants.

        On database failure, returns None (fail closed — falls through to
        static rules then default decision).
        """
        now = datetime.now(UTC).replace(tzinfo=None)
        try:
            with Session(get_engine()) as session:
                grants = session.exec(
                    select(TaskPermission).where(
                        TaskPermission.task_id == task_id,
                        TaskPermission.organization_id == organization_id,
                        TaskPermission.status == TaskPermissionStatus.ACTIVE,
                    )
                ).all()
        except Exception:
            logger.warning(
                "Database unavailable during task permission check for %s.%s on %s (task=%s) — failing closed",
                tool, action, scope, task_id, exc_info=True,
            )
            return None

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

        On database failure, returns None (fail closed — falls through to
        static rules then default decision).
        """
        import aiperture.config

        settings = aiperture.config.settings
        if not settings.permission_learning_enabled:
            return None

        # Never auto-approve HIGH or CRITICAL risk actions
        from aiperture.permissions.risk import classify_risk

        risk = classify_risk(tool, action, scope)
        if risk.tier in (RiskTier.HIGH, RiskTier.CRITICAL):
            logger.debug(
                "Skipping auto-learn for %s.%s on %s — risk tier is %s",
                tool, action, scope, risk.tier.value,
            )
            return None

        try:
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
        except Exception:
            logger.warning(
                "Database unavailable during learned permission check for %s.%s on %s — failing closed",
                tool, action, scope, exc_info=True,
            )
            return None

        if not logs:
            return None

        # Exclude rubber-stamped decisions (`:rapid` suffix)
        matching = [
            log for log in logs
            if fnmatch.fnmatch(scope, log.scope) and not log.decided_by.endswith(":rapid")
        ]

        if len(matching) < settings.permission_learning_min_decisions:
            return None

        # Temporal decay: skip auto-approval if most recent decision is too old
        most_recent = max(log.created_at for log in matching)
        age_days = (datetime.now(UTC).replace(tzinfo=None) - most_recent).total_seconds() / 86400
        if age_days > settings.pattern_max_age_days:
            logger.info(
                "Pattern expired for %s.%s on %s (last decision %.0f days ago, max %d)",
                tool, action, scope, age_days, settings.pattern_max_age_days,
            )
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
        from aiperture.permissions.resource import extract_resource

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
            # Notify permission log hook plugin (fire-and-forget)
            from aiperture import plugins

            hook = plugins.get("permission_log_hook")
            if hook is not None:
                try:
                    hook.on_permission_logged(log_entry)
                except Exception:
                    logger.debug("Permission log hook failed", exc_info=True)
        except Exception:
            logger.error("Failed to log permission decision for %s.%s", tool, action, exc_info=True)
        return log_entry
