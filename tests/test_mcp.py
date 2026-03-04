"""Tests for the MCP server tools — direct function calls, no transport needed.

Each tool is a regular Python function decorated with @mcp.tool().
They return JSON strings (or plain text) that we parse and assert on.
The `fresh_db` autouse fixture in conftest.py handles per-test DB reset.

Note: approve_action, deny_action, revoke_permission_pattern, and
report_tool_execution are intentionally NOT exposed as MCP tools (see
mcp_server.py docstring for security rationale). Tests that need to record
human decisions use the engine's record_human_decision directly.
"""

import json

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from aiperture.mcp_server import (
    check_permission,
    explain_action,
    get_audit_trail,
    get_config,
    get_cost_summary,
    get_permission_patterns,
    store_artifact,
    verify_artifact,
)


# ---- Wiring test --------------------------------------------------------


class TestMCPToolsImportable:
    """Wiring: all MCP tools are importable from aiperture.mcp_server."""

    def test_all_tools_importable(self):
        """Every MCP tool function is importable from the public module."""
        for fn in (
            check_permission,
            explain_action,
            get_permission_patterns,
            store_artifact,
            verify_artifact,
            get_cost_summary,
            get_audit_trail,
            get_config,
        ):
            assert callable(fn), f"{fn.__name__} is not callable"

    def test_update_config_not_exposed(self):
        """update_config is NOT an MCP tool — config changes only via CLI/REST."""
        import aiperture.mcp_server as mod
        assert not hasattr(mod, "update_config"), "update_config should not be an MCP tool"

    def test_approve_action_not_exposed(self):
        """approve_action is NOT an MCP tool — agents can relay HMAC tokens to self-approve."""
        import aiperture.mcp_server as mod
        assert not hasattr(mod, "approve_action"), "approve_action should not be an MCP tool"

    def test_deny_action_not_exposed(self):
        """deny_action is NOT an MCP tool — agents can poison learning with fake denials."""
        import aiperture.mcp_server as mod
        assert not hasattr(mod, "deny_action"), "deny_action should not be an MCP tool"

    def test_revoke_permission_pattern_not_exposed(self):
        """revoke_permission_pattern is NOT an MCP tool — agents can DoS the learning system."""
        import aiperture.mcp_server as mod
        assert not hasattr(mod, "revoke_permission_pattern"), "revoke_permission_pattern should not be an MCP tool"

    def test_report_tool_execution_not_exposed(self):
        """report_tool_execution is NOT an MCP tool — agents can fabricate compliance data."""
        import aiperture.mcp_server as mod
        assert not hasattr(mod, "report_tool_execution"), "report_tool_execution should not be an MCP tool"


# ---- check_permission ----------------------------------------------------


class TestCheckPermission:
    """check_permission returns enriched JSON verdict."""

    def test_check_permission_returns_json_with_decision(self):
        """Basic check with no rules returns deny with risk assessment."""
        result = json.loads(check_permission(
            tool="shell",
            action="execute",
            scope="ls -la",
        ))
        assert result["decision"] in ("allow", "deny", "ask")
        assert "risk" in result
        assert result["risk"]["tier"] in ("low", "medium", "high", "critical")
        assert isinstance(result["risk"]["score"], float)
        assert isinstance(result["risk"]["factors"], list)
        assert isinstance(result["risk"]["reversible"], bool)

    def test_check_permission_ask_with_no_rules(self):
        """No static rules and no learned patterns means ask (default)."""
        result = json.loads(check_permission(
            tool="filesystem",
            action="write",
            scope="production/db.conf",
        ))
        assert result["decision"] == "ask"

    def test_check_permission_ask_has_challenge(self):
        """ASK verdict includes HMAC challenge for HTTP API approve/deny flow."""
        result = json.loads(check_permission(
            tool="shell", action="execute", scope="deploy.sh",
        ))
        assert result["decision"] == "ask"
        assert result["challenge"]
        assert result["challenge_nonce"]
        assert result["challenge_issued_at"] > 0

    def test_check_permission_critical_risk_rm_rf(self):
        """rm -rf / is always CRITICAL risk."""
        result = json.loads(check_permission(
            tool="shell",
            action="execute",
            scope="rm -rf /",
        ))
        assert result["decision"] == "ask"
        assert result["risk"]["tier"] == "critical"
        assert result["risk"]["score"] == 1.0
        assert result["risk"]["reversible"] is False

    def test_check_permission_has_explanation(self):
        """Enriched verdict includes explanation field."""
        result = json.loads(check_permission(
            tool="shell",
            action="execute",
            scope="rm -rf ./build/",
        ))
        # check_permission always passes enrich=True
        assert "explanation" in result

    def test_check_permission_has_recommendation(self):
        """Enriched verdict includes recommendation fields."""
        result = json.loads(check_permission(
            tool="filesystem",
            action="read",
            scope="src/main.py",
        ))
        assert "recommendation" in result
        assert "recommendation_code" in result

    def test_check_permission_creates_audit_event(self):
        """Every check_permission call creates an audit event."""
        check_permission(tool="shell", action="execute", scope="ls")
        trail = get_audit_trail()
        assert "permission.check" in trail

    def test_check_permission_with_session_id(self):
        """Session memory: approve via engine, then check with same session reuses decision."""
        from aiperture.mcp_server import _engine
        from aiperture.models.permission import PermissionDecision
        from aiperture.permissions.challenge import create_challenge

        # Create a valid challenge and record approval via engine directly
        ch = create_challenge("shell", "execute", "test.sh", organization_id="default", session_id="session-xyz")
        _engine.record_human_decision(
            tool="shell",
            action="execute",
            scope="test.sh",
            decision=PermissionDecision.ALLOW,
            decided_by="user-1",
            session_id="session-xyz",
            organization_id="default",
            challenge=ch.token,
            challenge_nonce=ch.nonce,
            challenge_issued_at=ch.issued_at,
        )

        # Now check with same session_id — should be allowed from session memory
        result = json.loads(check_permission(
            tool="shell",
            action="execute",
            scope="test.sh",
            session_id="session-xyz",
        ))
        assert result["decision"] == "allow"
        assert result["decided_by"] == "session_memory"


# ---- explain_action ------------------------------------------------------


class TestExplainAction:
    """explain_action returns JSON with explanation and risk."""

    def test_explain_shell_execute(self):
        """Shell execute gets a template-based explanation."""
        result = json.loads(explain_action(
            tool="shell",
            action="execute",
            scope="ls -la",
        ))
        assert "explanation" in result
        assert "ls -la" in result["explanation"]
        assert "risk" in result
        assert result["risk"]["tier"] in ("low", "medium", "high", "critical")
        assert isinstance(result["risk"]["score"], float)
        assert isinstance(result["risk"]["factors"], list)
        assert isinstance(result["risk"]["reversible"], bool)

    def test_explain_destructive_command(self):
        """Destructive command gets annotations in explanation."""
        result = json.loads(explain_action(
            tool="shell",
            action="execute",
            scope="rm -rf ./build/",
        ))
        explanation = result["explanation"]
        assert "rm -rf" in explanation
        # Should have at least one annotation (destructive, irreversible, etc.)
        assert "(" in explanation, "Expected annotations in parentheses"

    def test_explain_filesystem_read(self):
        """Filesystem read uses the template."""
        result = json.loads(explain_action(
            tool="filesystem",
            action="read",
            scope="src/main.py",
        ))
        assert "Read file" in result["explanation"]
        assert result["risk"]["tier"] == "low"

    def test_explain_unknown_tool_action(self):
        """Unknown tool/action falls back to generic explanation."""
        result = json.loads(explain_action(
            tool="custom_tool",
            action="unknown_action",
            scope="some_scope",
        ))
        assert "explanation" in result
        assert "risk" in result
        # Fallback template includes tool and action names
        assert "custom_tool" in result["explanation"] or "unknown_action" in result["explanation"]

    def test_explain_critical_command(self):
        """rm -rf / is critical."""
        result = json.loads(explain_action(
            tool="shell",
            action="execute",
            scope="rm -rf /",
        ))
        assert result["risk"]["tier"] == "critical"
        assert result["risk"]["score"] == 1.0
        assert result["risk"]["reversible"] is False


# ---- get_permission_patterns ---------------------------------------------


class TestGetPermissionPatterns:
    """get_permission_patterns returns learned patterns or a message."""

    def test_no_patterns_returns_message(self):
        """When no decisions recorded, returns informational text."""
        result = get_permission_patterns()
        assert "No permission patterns" in result
        assert "need" in result.lower() or "more" in result.lower()

    def test_patterns_with_sufficient_decisions(self):
        """After enough decisions, patterns are surfaced."""
        import aiperture.config
        aiperture.config.settings.permission_learning_enabled = False  # don't auto-decide

        # Record 10 human approvals for the same pattern (bypass engine, insert directly)
        from aiperture.mcp_server import _engine
        from aiperture.models.permission import PermissionDecision
        from aiperture.permissions.challenge import create_challenge

        for i in range(10):
            ch = create_challenge("filesystem", "read", "docs/*", organization_id="default")
            _engine.record_human_decision(
                tool="filesystem",
                action="read",
                scope="docs/*",
                decision=PermissionDecision.ALLOW,
                decided_by=f"user-{i % 3}",
                organization_id="default",
                challenge=ch.token,
                challenge_nonce=ch.nonce,
                challenge_issued_at=ch.issued_at,
            )

        result = get_permission_patterns(min_decisions=5)
        assert "Learned permission patterns" in result
        assert "filesystem.read" in result
        assert "docs/*" in result
        # Should show approval stats
        assert "approved" in result
        assert "decisions" in result

    def test_patterns_with_custom_org(self):
        """Patterns are org-scoped."""
        result = get_permission_patterns(organization_id="nonexistent-org")
        assert "No permission patterns" in result


# ---- store_artifact ------------------------------------------------------


class TestStoreArtifact:
    """store_artifact stores content and returns JSON with ID and hash."""

    def test_store_returns_artifact_id_and_hash(self):
        """Stored artifact has ID, content_hash, and verified status."""
        result = json.loads(store_artifact(content="hello world"))
        assert "artifact_id" in result
        assert len(result["artifact_id"]) > 0
        assert "content_hash" in result
        assert len(result["content_hash"]) == 64  # SHA-256 hex = 64 chars
        assert result["verification_status"] == "verified"

    def test_store_with_metadata(self):
        """All metadata parameters are accepted."""
        result = json.loads(store_artifact(
            content="test output from shell",
            tool_name="shell",
            summary="ran unit tests",
            task_id="task-99",
            artifact_type="tool_call",
            tokens_input=100,
            tokens_output=50,
            cost_usd=0.005,
            model_used="claude-sonnet-4-5",
            provider_used="anthropic",
            organization_id="acme",
        ))
        assert result["artifact_id"]
        assert result["verification_status"] == "verified"

    def test_store_creates_audit_event(self):
        """Storing an artifact creates an audit event."""
        store_artifact(content="audited content", summary="test artifact")
        trail = get_audit_trail()
        assert "artifact.stored" in trail

    def test_store_consistent_hash(self):
        """Same content always produces the same hash."""
        r1 = json.loads(store_artifact(content="deterministic"))
        r2 = json.loads(store_artifact(content="deterministic"))
        assert r1["content_hash"] == r2["content_hash"]
        # But they get different artifact IDs
        assert r1["artifact_id"] != r2["artifact_id"]

    def test_store_different_content_different_hash(self):
        """Different content produces different hashes."""
        r1 = json.loads(store_artifact(content="content A"))
        r2 = json.loads(store_artifact(content="content B"))
        assert r1["content_hash"] != r2["content_hash"]


# ---- verify_artifact -----------------------------------------------------


class TestVerifyArtifact:
    """verify_artifact re-checks SHA-256 integrity."""

    def test_verify_stored_artifact_passes(self):
        """A freshly stored artifact verifies successfully."""
        stored = json.loads(store_artifact(content="verify me"))
        artifact_id = stored["artifact_id"]

        result = json.loads(verify_artifact(artifact_id=artifact_id))
        assert result["artifact_id"] == artifact_id
        assert result["verification_status"] == "verified"
        assert result["content_hash"] == stored["content_hash"]

    def test_verify_nonexistent_artifact_raises_tool_error(self):
        """Verifying a nonexistent artifact raises ToolError."""
        with pytest.raises(ToolError, match="not found"):
            verify_artifact(artifact_id="nonexistent-id-12345")

    def test_verify_preserves_hash(self):
        """Verification does not change the content hash."""
        stored = json.loads(store_artifact(content="immutable content"))
        original_hash = stored["content_hash"]

        verified = json.loads(verify_artifact(artifact_id=stored["artifact_id"]))
        assert verified["content_hash"] == original_hash


# ---- get_cost_summary ----------------------------------------------------


class TestGetCostSummary:
    """get_cost_summary returns JSON cost breakdown."""

    def test_empty_cost_summary(self):
        """No artifacts means zero costs."""
        result = json.loads(get_cost_summary())
        assert result["total_cost_usd"] == 0
        assert result["total_tokens_input"] == 0
        assert result["total_tokens_output"] == 0
        assert result["total_artifacts"] == 0
        assert result["by_provider"] == {}
        assert result["by_model"] == {}

    def test_cost_summary_with_artifacts(self):
        """Costs accumulate across stored artifacts."""
        store_artifact(
            content="response 1",
            tokens_input=100,
            tokens_output=50,
            cost_usd=0.01,
            provider_used="anthropic",
            model_used="claude-sonnet-4-5",
        )
        store_artifact(
            content="response 2",
            tokens_input=200,
            tokens_output=100,
            cost_usd=0.02,
            provider_used="openai",
            model_used="gpt-4o",
        )

        result = json.loads(get_cost_summary())
        assert result["total_cost_usd"] == pytest.approx(0.03)
        assert result["total_tokens_input"] == 300
        assert result["total_tokens_output"] == 150
        assert result["total_artifacts"] == 2
        assert result["by_provider"]["anthropic"] == pytest.approx(0.01)
        assert result["by_provider"]["openai"] == pytest.approx(0.02)
        assert result["by_model"]["claude-sonnet-4-5"] == pytest.approx(0.01)
        assert result["by_model"]["gpt-4o"] == pytest.approx(0.02)

    def test_cost_summary_scoped_by_task(self):
        """task_id filter scopes the cost summary."""
        store_artifact(
            content="task A output",
            task_id="task-A",
            cost_usd=0.05,
            tokens_input=500,
        )
        store_artifact(
            content="task B output",
            task_id="task-B",
            cost_usd=0.10,
            tokens_input=1000,
        )

        result = json.loads(get_cost_summary(task_id="task-A"))
        assert result["total_cost_usd"] == pytest.approx(0.05)
        assert result["total_tokens_input"] == 500
        assert result["total_artifacts"] == 1

    def test_cost_summary_scoped_by_organization(self):
        """organization_id filter scopes the cost summary."""
        store_artifact(
            content="org1 output",
            organization_id="org1",
            cost_usd=0.01,
        )
        store_artifact(
            content="org2 output",
            organization_id="org2",
            cost_usd=0.99,
        )

        result = json.loads(get_cost_summary(organization_id="org1"))
        assert result["total_cost_usd"] == pytest.approx(0.01)
        assert result["total_artifacts"] == 1


# ---- get_audit_trail -----------------------------------------------------


class TestGetAuditTrail:
    """get_audit_trail returns text summary of audit events."""

    def test_empty_audit_trail(self):
        """No events returns informational message."""
        result = get_audit_trail()
        assert "No audit events" in result

    def test_audit_trail_after_check(self):
        """Permission check creates an audit event in the trail."""
        check_permission(tool="shell", action="execute", scope="ls")
        result = get_audit_trail()
        assert "Audit trail" in result
        assert "permission.check" in result
        assert "shell.execute" in result

    def test_audit_trail_after_store(self):
        """Storing an artifact creates an audit event."""
        store_artifact(content="audit this", summary="test artifact")
        result = get_audit_trail()
        assert "artifact.stored" in result

    def test_audit_trail_filter_by_event_type(self):
        """event_type filter narrows results."""
        check_permission(tool="shell", action="execute", scope="ls")
        store_artifact(content="something")

        # Filter to only permission events
        result = get_audit_trail(event_type="permission.check")
        assert "permission.check" in result
        # artifact.stored should not be in filtered result
        assert "artifact.stored" not in result

    def test_audit_trail_shows_multiple_events(self):
        """Multiple actions create multiple audit entries."""
        check_permission(tool="shell", action="execute", scope="ls")
        check_permission(tool="filesystem", action="read", scope="foo.py")
        store_artifact(content="output")

        result = get_audit_trail()
        assert "Audit trail" in result
        # Should show the count
        assert "events" in result

    def test_audit_trail_respects_limit(self):
        """limit parameter caps the number of events."""
        for i in range(5):
            check_permission(tool="shell", action="execute", scope=f"cmd-{i}")

        result = get_audit_trail(limit=2)
        # Should contain "2 events" in the header
        assert "2 events" in result

    def test_audit_trail_scoped_by_organization(self):
        """organization_id filter scopes audit events."""
        check_permission(
            tool="shell", action="execute", scope="ls",
            organization_id="org-alpha",
        )
        check_permission(
            tool="shell", action="execute", scope="pwd",
            organization_id="org-beta",
        )

        result = get_audit_trail(organization_id="org-alpha")
        assert "permission.check" in result
        # Only org-alpha's event should appear
        assert "1 events" in result


# ---- Integration: end-to-end workflow ------------------------------------


class TestEndToEndWorkflow:
    """Integration: full permission lifecycle via MCP tools and engine."""

    def test_check_approve_recheck_flow(self):
        """Full flow: check (ask) -> approve via engine -> check with session (allow)."""
        from aiperture.mcp_server import _engine
        from aiperture.models.permission import PermissionDecision
        from aiperture.permissions.challenge import create_challenge

        # Step 1: Initial check returns ask (no rules, no history)
        r1 = json.loads(check_permission(
            tool="shell",
            action="execute",
            scope="deploy.sh",
            session_id="session-e2e",
        ))
        assert r1["decision"] == "ask"

        # Step 2: Human approves via engine (simulating HTTP API or hook path)
        ch = create_challenge("shell", "execute", "deploy.sh", organization_id="default", session_id="session-e2e")
        _engine.record_human_decision(
            tool="shell",
            action="execute",
            scope="deploy.sh",
            decision=PermissionDecision.ALLOW,
            decided_by="admin",
            session_id="session-e2e",
            organization_id="default",
            challenge=ch.token,
            challenge_nonce=ch.nonce,
            challenge_issued_at=ch.issued_at,
        )

        # Step 3: Same session check is now allowed via session memory
        r2 = json.loads(check_permission(
            tool="shell",
            action="execute",
            scope="deploy.sh",
            session_id="session-e2e",
        ))
        assert r2["decision"] == "allow"
        assert r2["decided_by"] == "session_memory"

    def test_store_verify_cost_audit_flow(self):
        """Full flow: store -> verify -> cost summary -> audit trail."""
        # Step 1: Store artifact
        stored = json.loads(store_artifact(
            content="build output: SUCCESS",
            tool_name="shell",
            summary="build result",
            task_id="task-build",
            tokens_input=50,
            cost_usd=0.001,
            provider_used="anthropic",
            model_used="claude-sonnet-4-5",
        ))
        artifact_id = stored["artifact_id"]

        # Step 2: Verify integrity
        verified = json.loads(verify_artifact(artifact_id=artifact_id))
        assert verified["verification_status"] == "verified"

        # Step 3: Cost summary reflects the stored artifact
        costs = json.loads(get_cost_summary(task_id="task-build"))
        assert costs["total_cost_usd"] == pytest.approx(0.001)
        assert costs["total_tokens_input"] == 50
        assert costs["by_provider"]["anthropic"] == pytest.approx(0.001)

        # Step 4: Audit trail has both store and check events
        trail = get_audit_trail()
        assert "artifact.stored" in trail

    def test_deny_persists_in_session(self):
        """Denied actions stay denied for the session (via engine)."""
        from aiperture.mcp_server import _engine
        from aiperture.models.permission import PermissionDecision
        from aiperture.permissions.challenge import create_challenge

        ch = create_challenge("database", "drop", "production.users", organization_id="default", session_id="session-safe")
        _engine.record_human_decision(
            tool="database",
            action="drop",
            scope="production.users",
            decision=PermissionDecision.DENY,
            decided_by="dba",
            session_id="session-safe",
            organization_id="default",
            challenge=ch.token,
            challenge_nonce=ch.nonce,
            challenge_issued_at=ch.issued_at,
        )

        result = json.loads(check_permission(
            tool="database",
            action="drop",
            scope="production.users",
            session_id="session-safe",
        ))
        assert result["decision"] == "deny"
        assert result["decided_by"] == "session_memory"

    def test_agent_self_approval_blocked(self):
        """approve_action and deny_action are not exposed as MCP tools.

        The agent cannot self-approve because the tools don't exist in the
        MCP server. The HMAC challenge is still included in verdicts for
        HTTP API consumers with their own UI layers.
        """
        import aiperture.mcp_server as mod

        # Verify the dangerous tools are not exposed
        assert not hasattr(mod, "approve_action")
        assert not hasattr(mod, "deny_action")
        assert not hasattr(mod, "revoke_permission_pattern")
        assert not hasattr(mod, "report_tool_execution")

        # check_permission still works and returns ASK with challenge
        r1 = json.loads(check_permission(
            tool="shell", action="execute", scope="dangerous.sh",
        ))
        assert r1["decision"] == "ask"
        assert r1["challenge"]  # still present for HTTP API consumers

        # Without approve/deny tools, the agent has no way to record decisions
        # via MCP. The action stays as "ask" indefinitely.
        r2 = json.loads(check_permission(
            tool="shell", action="execute", scope="dangerous.sh",
        ))
        assert r2["decision"] == "ask"
