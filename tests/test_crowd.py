"""Tests for the crowd signal / org stats aggregator."""

from aperture.models import OrgSignal, PermissionDecision
from aperture.permissions import (
    PermissionEngine,
    compute_auto_approve_distance,
    get_org_signal,
)
from aperture.permissions.challenge import create_challenge


def _make_challenge(tool: str, action: str, scope: str, organization_id: str = "default", session_id: str = "") -> dict:
    """Helper: create valid challenge kwargs for record_human_decision."""
    token = create_challenge(tool, action, scope, organization_id=organization_id, session_id=session_id)
    return {
        "challenge": token.token,
        "challenge_nonce": token.nonce,
        "challenge_issued_at": token.issued_at,
    }


class TestOrgSignal:
    """get_org_signal() querying and aggregation."""

    def test_returns_none_with_no_history(self):
        signal = get_org_signal("shell", "execute", "unknown-cmd")
        assert signal is None

    def test_returns_signal_with_history(self):
        engine = PermissionEngine()
        for i in range(5):
            engine.record_human_decision(
                tool="filesystem",
                action="read",
                scope="docs/*",
                decision=PermissionDecision.ALLOW,
                decided_by=f"user-{i}",
                organization_id="crowd-test-org",
                **_make_challenge("filesystem", "read", "docs/*", organization_id="crowd-test-org"),
            )

        signal = get_org_signal("filesystem", "read", "docs/*", organization_id="crowd-test-org")
        assert signal is not None
        assert signal.total_decisions == 5
        assert signal.allow_count == 5
        assert signal.allow_rate == 1.0
        assert signal.unique_humans == 5

    def test_mixed_decisions(self):
        engine = PermissionEngine()
        for i in range(3):
            engine.record_human_decision(
                tool="api", action="post", scope="users/*",
                decision=PermissionDecision.ALLOW,
                decided_by=f"user-{i}",
                organization_id="crowd-mix-org",
                **_make_challenge("api", "post", "users/*", organization_id="crowd-mix-org"),
            )
        for i in range(2):
            engine.record_human_decision(
                tool="api", action="post", scope="users/*",
                decision=PermissionDecision.DENY,
                decided_by=f"user-{i}",
                organization_id="crowd-mix-org",
                **_make_challenge("api", "post", "users/*", organization_id="crowd-mix-org"),
            )

        signal = get_org_signal("api", "post", "users/*", organization_id="crowd-mix-org")
        assert signal is not None
        assert signal.total_decisions == 5
        assert signal.allow_count == 3
        assert signal.deny_count == 2
        assert 0.55 < signal.allow_rate < 0.65


class TestTrend:
    """compute_trend() analysis."""

    def test_insufficient_data(self):
        # Need PermissionLog objects — use engine to create them
        engine = PermissionEngine()
        for i in range(2):
            engine.record_human_decision(
                tool="shell", action="execute", scope="trend-test-cmd",
                decision=PermissionDecision.ALLOW,
                decided_by=f"user-{i}",
                organization_id="trend-org",
                **_make_challenge("shell", "execute", "trend-test-cmd", organization_id="trend-org"),
            )
        signal = get_org_signal("shell", "execute", "trend-test-cmd", organization_id="trend-org")
        # With only 2 decisions, trend should be insufficient_data or new
        assert signal is not None
        assert signal.trend in ("insufficient_data", "new")


class TestAutoApproveDistance:
    """compute_auto_approve_distance() calculation."""

    def test_already_approved(self):
        signal = OrgSignal(
            total_decisions=20, allow_count=19, deny_count=1,
            allow_rate=0.95, unique_humans=5,
            last_decision_at=None, first_decision_at=None,
            trend="stable", velocity=1.0,
        )
        distance = compute_auto_approve_distance(signal, min_decisions=10, threshold=0.95)
        assert distance == 0

    def test_needs_more_allows(self):
        signal = OrgSignal(
            total_decisions=5, allow_count=4, deny_count=1,
            allow_rate=0.8, unique_humans=3,
            last_decision_at=None, first_decision_at=None,
            trend="stable", velocity=1.0,
        )
        distance = compute_auto_approve_distance(signal, min_decisions=10, threshold=0.95)
        assert distance is not None
        assert distance > 0

    def test_trending_deny_returns_none(self):
        signal = OrgSignal(
            total_decisions=10, allow_count=5, deny_count=5,
            allow_rate=0.5, unique_humans=3,
            last_decision_at=None, first_decision_at=None,
            trend="toward_deny", velocity=1.0,
        )
        distance = compute_auto_approve_distance(signal, min_decisions=10, threshold=0.95)
        assert distance is None
