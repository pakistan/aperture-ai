"""Tests for the permission engine — RBAC, ReBAC, learning, and enriched verdicts."""

from aperture.models import Permission, PermissionDecision, RiskTier
from aperture.permissions import PermissionEngine, PermissionLearner
from aperture.permissions.challenge import create_challenge


def _make_challenge(tool: str, action: str, scope: str, organization_id: str = "default", session_id: str = "") -> dict:
    """Helper: create valid challenge kwargs for record_human_decision."""
    token = create_challenge(tool, action, scope, organization_id=organization_id, session_id=session_id)
    return {
        "challenge": token.token,
        "challenge_nonce": token.nonce,
        "challenge_issued_at": token.issued_at,
    }


class TestStaticPermissions:
    """Static RBAC with glob matching."""

    def test_exact_match_allows(self):
        engine = PermissionEngine()
        rules = [Permission(tool="shell", action="execute", scope="ls", decision=PermissionDecision.ALLOW)]
        verdict = engine.check("shell", "execute", "ls", rules)
        assert verdict.decision == "allow"

    def test_no_match_denies(self):
        engine = PermissionEngine()
        rules = [Permission(tool="shell", action="execute", scope="ls", decision=PermissionDecision.ALLOW)]
        verdict = engine.check("shell", "execute", "rm -rf /", rules)
        assert verdict.decision == "deny"

    def test_glob_match(self):
        engine = PermissionEngine()
        rules = [Permission(tool="filesystem", action="read", scope="src/*.py", decision=PermissionDecision.ALLOW)]
        assert engine.check("filesystem", "read", "src/main.py", rules).decision == "allow"
        assert engine.check("filesystem", "read", "etc/passwd", rules).decision == "deny"

    def test_specificity_wins(self):
        engine = PermissionEngine()
        rules = [
            Permission(tool="filesystem", action="write", scope="*", decision=PermissionDecision.ALLOW),
            Permission(tool="filesystem", action="write", scope="production/*", decision=PermissionDecision.DENY),
        ]
        assert engine.check("filesystem", "write", "src/foo.py", rules).decision == "allow"
        assert engine.check("filesystem", "write", "production/db.conf", rules).decision == "deny"

    def test_ask_decision(self):
        engine = PermissionEngine()
        rules = [Permission(tool="api", action="*", scope="*", decision=PermissionDecision.ASK)]
        assert engine.check("api", "post", "users/delete", rules).decision == "ask"


class TestTaskPermissions:
    """Task-scoped ReBAC grants."""

    def test_task_grant_overrides_static(self):
        engine = PermissionEngine()
        rules = [Permission(tool="shell", action="execute", scope="*", decision=PermissionDecision.DENY)]

        # Without task grant, denied
        assert engine.check("shell", "execute", "deploy.sh", rules).decision == "deny"

        # Grant for this task
        engine.grant_task_permission(
            task_id="task-1",
            tool="shell",
            action="execute",
            scope="deploy.sh",
            decision=PermissionDecision.ALLOW,
            granted_by="admin",
        )

        # With task grant, allowed
        assert engine.check("shell", "execute", "deploy.sh", rules, task_id="task-1").decision == "allow"

    def test_task_grant_does_not_affect_other_tasks(self):
        engine = PermissionEngine()
        rules = [Permission(tool="shell", action="execute", scope="*", decision=PermissionDecision.DENY)]

        engine.grant_task_permission(
            task_id="task-1",
            tool="shell",
            action="execute",
            scope="*",
            decision=PermissionDecision.ALLOW,
            granted_by="admin",
        )

        # Different task still denied
        assert engine.check("shell", "execute", "anything", rules, task_id="task-2").decision == "deny"


class TestPermissionLearning:
    """Learning from human decisions."""

    def test_auto_approve_after_consistent_approvals(self):
        engine = PermissionEngine()
        import aperture.config
        aperture.config.settings.permission_learning_min_decisions = 5
        aperture.config.settings.auto_approve_threshold = 0.95

        # Record 10 human approvals
        for i in range(10):
            engine.record_human_decision(
                tool="filesystem",
                action="read",
                scope="docs/*",
                decision=PermissionDecision.ALLOW,
                decided_by=f"user-{i % 3}",
                organization_id="default",
                **_make_challenge("filesystem", "read", "docs/*"),
            )

        # Now check — should be auto-approved (no static rules needed)
        verdict = engine.check("filesystem", "read", "docs/readme.md", [])
        assert verdict.decision == "allow"

    def test_no_auto_decision_with_few_samples(self):
        engine = PermissionEngine()
        import aperture.config
        aperture.config.settings.permission_learning_min_decisions = 10

        # Only 3 decisions — not enough
        for _ in range(3):
            engine.record_human_decision(
                tool="shell",
                action="execute",
                scope="test.sh",
                decision=PermissionDecision.ALLOW,
                decided_by="user-1",
                **_make_challenge("shell", "execute", "test.sh"),
            )

        # Falls through to static rules (empty = deny)
        verdict = engine.check("shell", "execute", "test.sh", [])
        assert verdict.decision == "deny"

    def test_high_risk_actions_never_auto_approved(self):
        """HIGH/CRITICAL risk actions must always require human approval, even with strong history."""
        engine = PermissionEngine()
        import aperture.config
        aperture.config.settings.permission_learning_min_decisions = 3
        aperture.config.settings.auto_approve_threshold = 0.80

        # Record 20 human approvals of a destructive shell command
        for i in range(20):
            engine.record_human_decision(
                tool="shell",
                action="execute",
                scope="rm -rf ./build/",
                decision=PermissionDecision.ALLOW,
                decided_by=f"user-{i % 3}",
                organization_id="default",
                **_make_challenge("shell", "execute", "rm -rf ./build/"),
            )

        # Despite 20 approvals at 100% rate, this should NOT be auto-approved
        # because shell.execute on "rm -rf ./build/" is HIGH risk
        verdict = engine.check("shell", "execute", "rm -rf ./build/", [])
        assert verdict.decision == "deny", (
            f"HIGH risk action was auto-approved — expected deny, got {verdict.decision}"
        )

    def test_learner_detects_patterns(self):
        engine = PermissionEngine()
        import aperture.config
        aperture.config.settings.permission_learning_enabled = False  # disable auto for this test

        # Record 20 decisions: 19 allow, 1 deny = 95% approval
        for i in range(20):
            engine.record_human_decision(
                tool="api",
                action="post",
                scope="users/*",
                decision=PermissionDecision.ALLOW if i < 19 else PermissionDecision.DENY,
                decided_by=f"user-{i % 4}",
                **_make_challenge("api", "post", "users/*"),
            )

        learner = PermissionLearner()
        patterns = learner.detect_patterns(min_decisions=5)
        assert len(patterns) == 1
        assert patterns[0].tool == "api"
        assert patterns[0].approval_rate >= 0.95
        assert patterns[0].recommendation in ("auto_approve", "suggest_rule")


class TestVerdictEnrichment:
    """Enriched verdict responses."""

    def test_verdict_has_risk(self):
        engine = PermissionEngine()
        rules = [Permission(tool="shell", action="execute", scope="*", decision=PermissionDecision.ALLOW)]
        verdict = engine.check("shell", "execute", "rm -rf ./build/", rules)
        assert verdict.risk is not None
        assert verdict.risk.tier in (RiskTier.MEDIUM, RiskTier.HIGH, RiskTier.CRITICAL)

    def test_enriched_verdict_has_explanation(self):
        engine = PermissionEngine()
        rules = [Permission(tool="shell", action="execute", scope="*", decision=PermissionDecision.ALLOW)]
        verdict = engine.check("shell", "execute", "rm -rf ./build/", rules, enrich=True)
        assert verdict.explanation
        assert "rm -rf" in verdict.explanation

    def test_enriched_verdict_has_org_signal(self):
        engine = PermissionEngine()

        # Record some decisions first
        for i in range(5):
            engine.record_human_decision(
                tool="filesystem",
                action="read",
                scope="src/*",
                decision=PermissionDecision.ALLOW,
                decided_by=f"user-{i}",
                **_make_challenge("filesystem", "read", "src/*"),
            )

        verdict = engine.check("filesystem", "read", "src/main.py", [], enrich=True)
        assert verdict.org_signal is not None
        assert verdict.org_signal.total_decisions == 5
        assert verdict.org_signal.allow_rate == 1.0

    def test_verdict_to_dict(self):
        engine = PermissionEngine()
        rules = [Permission(tool="filesystem", action="read", scope="*", decision=PermissionDecision.ALLOW)]
        verdict = engine.check("filesystem", "read", "src/main.py", rules, enrich=True)
        d = verdict.to_dict()
        assert d["decision"] == "allow"
        assert "risk" in d
        assert d["risk"]["tier"] in ("low", "medium", "high", "critical")
        assert "explanation" in d

    def test_session_memory(self):
        engine = PermissionEngine()

        # Record a human approval with session_id
        engine.record_human_decision(
            tool="shell", action="execute", scope="test.sh",
            decision=PermissionDecision.ALLOW,
            decided_by="user-1",
            session_id="session-abc",
            **_make_challenge("shell", "execute", "test.sh", session_id="session-abc"),
        )

        # Same check with same session_id → cached
        verdict = engine.check("shell", "execute", "test.sh", [], session_id="session-abc")
        assert verdict.decision == "allow"
        assert verdict.decided_by == "session_memory"

    def test_critical_risk_for_rm_rf_root(self):
        engine = PermissionEngine()
        verdict = engine.check("shell", "execute", "rm -rf /", [])
        assert verdict.risk.tier == RiskTier.CRITICAL
        assert verdict.risk.score == 1.0
        assert not verdict.risk.reversible
