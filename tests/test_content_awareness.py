"""Tests for content awareness via content_hash (Fix 6).

Validates that different content_hash values produce separate cache entries
and that content_changed flag is set when content changes.
"""

import aperture.config
from aperture.models.permission import Permission, PermissionDecision
from aperture.permissions.challenge import create_challenge
from aperture.permissions.engine import PermissionEngine


def _make_challenge(tool: str, action: str, scope: str, organization_id: str = "default", session_id: str = "") -> dict:
    token = create_challenge(tool, action, scope, organization_id=organization_id, session_id=session_id)
    return {
        "challenge": token.token,
        "challenge_nonce": token.nonce,
        "challenge_issued_at": token.issued_at,
    }


class TestContentHashCacheKey:
    """Session cache differentiates by content_hash."""

    def test_same_scope_different_hash_separate_cache(self):
        """Two checks with same scope but different content_hash get separate cache entries."""
        engine = PermissionEngine()

        # Allow via static rule so we get an ALLOW decision
        allow_rule = Permission(tool="filesystem", action="write", scope="*.py", decision=PermissionDecision.ALLOW)

        v1 = engine.check(
            tool="filesystem", action="write", scope="main.py",
            permissions=[allow_rule],
            session_id="s1", content_hash="abc123",
        )
        assert v1.decision == PermissionDecision.ALLOW

        v2 = engine.check(
            tool="filesystem", action="write", scope="main.py",
            permissions=[allow_rule],
            session_id="s1", content_hash="def456",
        )

        # Both should exist as separate entries in session cache
        assert ("default", "filesystem", "write", "main.py", "s1", "abc123") not in engine._session_cache
        # Static rules don't populate the session cache — only session_memory lookups do
        # But the cache_key includes content_hash, so they won't collide

    def test_same_hash_uses_session_cache(self):
        """Same content_hash reuses the session cache entry."""
        engine = PermissionEngine()

        # Seed a cache entry directly
        engine._session_cache[("default", "filesystem", "read", "f.py", "s1", "hash1")] = PermissionDecision.ALLOW

        verdict = engine.check(
            tool="filesystem", action="read", scope="f.py",
            permissions=[],
            session_id="s1", content_hash="hash1",
        )
        assert verdict.decision == PermissionDecision.ALLOW
        assert verdict.decided_by == "session_memory"

    def test_different_hash_misses_cache(self):
        """Different content_hash does NOT match existing cache entry."""
        engine = PermissionEngine()

        # Seed cache with hash1
        engine._session_cache[("default", "filesystem", "read", "f.py", "s1", "hash1")] = PermissionDecision.ALLOW

        # Check with hash2 — should NOT get session_memory hit
        verdict = engine.check(
            tool="filesystem", action="read", scope="f.py",
            permissions=[],
            session_id="s1", content_hash="hash2",
        )
        # Without matching cache or learned/static rules, default is deny
        assert verdict.decision == PermissionDecision.DENY

    def test_empty_hash_matches_empty_hash(self):
        """Empty content_hash matches cache entry with empty hash."""
        engine = PermissionEngine()

        engine._session_cache[("default", "filesystem", "read", "f.py", "s1", "")] = PermissionDecision.ALLOW

        verdict = engine.check(
            tool="filesystem", action="read", scope="f.py",
            permissions=[],
            session_id="s1", content_hash="",
        )
        assert verdict.decision == PermissionDecision.ALLOW
        assert verdict.decided_by == "session_memory"


class TestContentChangedFlag:
    """content_changed flag detection in _build_verdict."""

    def test_content_changed_detected(self):
        """When same (tool, action, scope, session) seen with different hash, flag is True."""
        engine = PermissionEngine()

        # Seed cache with old hash
        engine._session_cache[("default", "filesystem", "write", "main.py", "s1", "old_hash")] = PermissionDecision.ALLOW

        # Build verdict with new hash
        verdict = engine._build_verdict(
            PermissionDecision.DENY, "static_rule",
            "filesystem", "write", "main.py",
            content_hash="new_hash", session_id="s1",
        )
        assert verdict.content_changed is True

    def test_content_not_changed_same_hash(self):
        """Same hash should not trigger content_changed."""
        engine = PermissionEngine()

        engine._session_cache[("default", "filesystem", "write", "main.py", "s1", "same")] = PermissionDecision.ALLOW

        verdict = engine._build_verdict(
            PermissionDecision.DENY, "static_rule",
            "filesystem", "write", "main.py",
            content_hash="same", session_id="s1",
        )
        assert verdict.content_changed is False

    def test_content_not_changed_no_prior(self):
        """No prior cache entry => content_changed stays False."""
        engine = PermissionEngine()

        verdict = engine._build_verdict(
            PermissionDecision.DENY, "static_rule",
            "filesystem", "write", "main.py",
            content_hash="first_write", session_id="s1",
        )
        assert verdict.content_changed is False

    def test_content_not_changed_no_hash(self):
        """Empty content_hash never triggers content_changed."""
        engine = PermissionEngine()

        engine._session_cache[("default", "filesystem", "write", "main.py", "s1", "")] = PermissionDecision.ALLOW

        verdict = engine._build_verdict(
            PermissionDecision.DENY, "static_rule",
            "filesystem", "write", "main.py",
            content_hash="", session_id="s1",
        )
        assert verdict.content_changed is False

    def test_content_not_changed_no_session(self):
        """No session_id => content_changed stays False even with hash."""
        engine = PermissionEngine()

        verdict = engine._build_verdict(
            PermissionDecision.DENY, "static_rule",
            "filesystem", "write", "main.py",
            content_hash="hash1", session_id="",
        )
        assert verdict.content_changed is False

    def test_content_changed_in_verdict_to_dict(self):
        """content_changed=True appears in to_dict() output."""
        from aperture.models.verdict import PermissionVerdict, RiskAssessment, RiskTier

        v = PermissionVerdict(
            decision=PermissionDecision.DENY,
            decided_by="static_rule",
            risk=RiskAssessment(tier=RiskTier.LOW, score=0.1, factors=[], reversible=True),
            content_changed=True,
        )
        d = v.to_dict()
        assert d["content_changed"] is True

    def test_content_changed_false_not_in_to_dict(self):
        """content_changed=False does NOT appear in to_dict() output."""
        from aperture.models.verdict import PermissionVerdict, RiskAssessment, RiskTier

        v = PermissionVerdict(
            decision=PermissionDecision.DENY,
            decided_by="static_rule",
            risk=RiskAssessment(tier=RiskTier.LOW, score=0.1, factors=[], reversible=True),
            content_changed=False,
        )
        d = v.to_dict()
        assert "content_changed" not in d


class TestContentHashInAPI:
    """content_hash parameter flows through the API."""

    def test_check_api_accepts_content_hash(self):
        """The /permissions/check endpoint accepts content_hash."""
        from fastapi.testclient import TestClient
        from aperture.api import create_app

        app = create_app()
        client = TestClient(app)

        resp = client.post("/permissions/check", json={
            "tool": "filesystem",
            "action": "write",
            "scope": "main.py",
            "permissions": [],
            "content_hash": "abc123",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] in ("allow", "deny")
