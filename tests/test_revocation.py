"""Tests for the revocation/unlearning mechanism (Fix 8)."""

import aperture.config
from aperture.models.permission import PermissionDecision, PermissionLog
from aperture.permissions.challenge import create_challenge
from aperture.permissions.crowd import get_org_signal
from aperture.permissions.engine import PermissionEngine
from aperture.permissions.learning import PermissionLearner
from sqlmodel import Session, select

from aperture.db import get_engine


def _make_challenge(tool: str, action: str, scope: str, organization_id: str = "default", session_id: str = "") -> dict:
    """Helper: create valid challenge kwargs for record_human_decision."""
    token = create_challenge(tool, action, scope, organization_id=organization_id, session_id=session_id)
    return {
        "challenge": token.token,
        "challenge_nonce": token.nonce,
        "challenge_issued_at": token.issued_at,
    }


def _seed_decisions(engine, tool, action, scope, count, org_id="revoke-org"):
    """Seed multiple approval decisions for a pattern."""
    for i in range(count):
        engine.record_human_decision(
            tool=tool,
            action=action,
            scope=scope,
            decision=PermissionDecision.ALLOW,
            decided_by=f"user-{i}",
            organization_id=org_id,
            **_make_challenge(tool, action, scope, organization_id=org_id),
        )


class TestRevokePattern:
    """PermissionEngine.revoke_pattern() behavior."""

    def test_revoke_removes_from_auto_approve(self):
        """After revoke, pattern no longer auto-approves."""
        engine = PermissionEngine()
        org = "revoke-auto-org"
        # Set low thresholds for this test
        aperture.config.settings.permission_learning_min_decisions = 3
        aperture.config.settings.auto_approve_threshold = 0.8

        _seed_decisions(engine, "filesystem", "read", "docs/*", 5, org)

        # Should auto-approve now
        verdict = engine.check(
            tool="filesystem", action="read", scope="docs/*",
            permissions=[], organization_id=org,
        )
        assert verdict.decision == PermissionDecision.ALLOW

        # Revoke
        count = engine.revoke_pattern("filesystem", "read", "docs/*", "admin", org)
        assert count == 5

        # Should no longer auto-approve
        verdict = engine.check(
            tool="filesystem", action="read", scope="docs/*",
            permissions=[], organization_id=org,
        )
        assert verdict.decision != PermissionDecision.ALLOW

    def test_revoke_preserves_audit_trail(self):
        """Revoked decisions still exist in DB with revoked_at set."""
        engine = PermissionEngine()
        org = "revoke-audit-org"

        _seed_decisions(engine, "api", "post", "users/*", 3, org)

        engine.revoke_pattern("api", "post", "users/*", "admin", org)

        with Session(get_engine()) as session:
            logs = session.exec(
                select(PermissionLog).where(
                    PermissionLog.organization_id == org,
                    PermissionLog.tool == "api",
                    PermissionLog.action == "post",
                )
            ).all()

        # All logs still exist
        assert len(logs) >= 3
        # Human decision logs should have revoked_at set
        human_logs = [l for l in logs if l.decided_by.startswith("human:")]
        assert all(l.revoked_at is not None for l in human_logs)

    def test_revoke_clears_session_cache(self):
        """Session cache entries for revoked pattern are removed."""
        engine = PermissionEngine()
        # Add to session cache
        engine._session_cache[("default", "shell", "execute", "ls*", "sess1", "")] = PermissionDecision.ALLOW
        engine._session_cache[("default", "shell", "execute", "cat*", "sess1", "")] = PermissionDecision.ALLOW

        engine.revoke_pattern("shell", "execute", "ls*", "admin")

        # ls* should be removed, cat* should remain
        assert ("default", "shell", "execute", "ls*", "sess1", "") not in engine._session_cache
        assert ("default", "shell", "execute", "cat*", "sess1", "") in engine._session_cache

    def test_revoke_idempotent(self):
        """Revoking same pattern twice does not error."""
        engine = PermissionEngine()
        org = "revoke-idem-org"

        _seed_decisions(engine, "filesystem", "read", "*.py", 3, org)

        count1 = engine.revoke_pattern("filesystem", "read", "*.py", "admin", org)
        count2 = engine.revoke_pattern("filesystem", "read", "*.py", "admin", org)

        assert count1 == 3
        assert count2 == 0  # already revoked

    def test_revoke_with_glob_scope(self):
        """Revoking with glob matches multiple scopes."""
        engine = PermissionEngine()
        org = "revoke-glob-org"

        _seed_decisions(engine, "shell", "execute", "ls -la", 2, org)
        _seed_decisions(engine, "shell", "execute", "ls -R", 2, org)

        # Revoke with glob pattern
        count = engine.revoke_pattern("shell", "execute", "ls*", "admin", org)
        assert count == 4  # both patterns matched


class TestCrowdSignalExcludesRevoked:
    """get_org_signal() excludes revoked decisions."""

    def test_crowd_signal_excludes_revoked(self):
        engine = PermissionEngine()
        org = "revoke-crowd-org"

        _seed_decisions(engine, "filesystem", "read", "src/*", 5, org)

        signal_before = get_org_signal("filesystem", "read", "src/*", org)
        assert signal_before is not None
        assert signal_before.total_decisions == 5

        engine.revoke_pattern("filesystem", "read", "src/*", "admin", org)

        signal_after = get_org_signal("filesystem", "read", "src/*", org)
        assert signal_after is None  # no non-revoked decisions


class TestLearnerExcludesRevoked:
    """PermissionLearner.detect_patterns() excludes revoked decisions."""

    def test_learner_excludes_revoked(self):
        engine = PermissionEngine()
        learner = PermissionLearner()
        org = "revoke-learn-org"

        _seed_decisions(engine, "filesystem", "list", "docs/*", 10, org)

        patterns_before = learner.detect_patterns(org, min_decisions=5)
        assert any(p.tool == "filesystem" and p.action == "list" for p in patterns_before)

        engine.revoke_pattern("filesystem", "list", "docs/*", "admin", org)

        patterns_after = learner.detect_patterns(org, min_decisions=5)
        assert not any(p.tool == "filesystem" and p.action == "list" for p in patterns_after)
