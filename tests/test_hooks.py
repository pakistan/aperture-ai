"""Tests for Claude Code hook integration."""

import time

from fastapi.testclient import TestClient

from aiperture.api import create_app
from aiperture.hooks.pending_tracker import PendingRequest, PendingTracker
from aiperture.hooks.tool_mapping import map_tool
from aiperture.models.permission import PermissionDecision
from aiperture.permissions.engine import PermissionEngine


# --- Tool mapping tests ---


class TestToolMapping:

    def test_bash_command(self):
        result = map_tool("Bash", {"command": "npm test"})
        assert result == ("shell", "execute", "npm test")

    def test_edit_file(self):
        result = map_tool("Edit", {"file_path": "/src/main.py", "old_string": "x", "new_string": "y"})
        assert result == ("filesystem", "write", "/src/main.py")

    def test_write_file(self):
        result = map_tool("Write", {"file_path": "/src/new.py", "content": "hello"})
        assert result == ("filesystem", "write", "/src/new.py")

    def test_read_file(self):
        result = map_tool("Read", {"file_path": "/src/main.py"})
        assert result == ("filesystem", "read", "/src/main.py")

    def test_glob(self):
        result = map_tool("Glob", {"pattern": "**/*.py"})
        assert result == ("filesystem", "read", "**/*.py")

    def test_grep(self):
        result = map_tool("Grep", {"pattern": "TODO", "path": "src/"})
        assert result == ("filesystem", "read", "src/:TODO")

    def test_grep_no_path(self):
        result = map_tool("Grep", {"pattern": "TODO"})
        assert result == ("filesystem", "read", "TODO")

    def test_webfetch(self):
        result = map_tool("WebFetch", {"url": "https://example.com", "prompt": "summarize"})
        assert result == ("web", "fetch", "https://example.com")

    def test_websearch(self):
        result = map_tool("WebSearch", {"query": "python docs"})
        assert result == ("web", "search", "python docs")

    def test_notebook_edit(self):
        result = map_tool("NotebookEdit", {"notebook_path": "/notebooks/analysis.ipynb", "new_source": "x"})
        assert result == ("filesystem", "write", "/notebooks/analysis.ipynb")

    def test_agent_tool(self):
        result = map_tool("Agent", {"subagent_type": "Explore", "description": "find routes"})
        assert result == ("agent", "spawn", "Explore:find routes")

    def test_mcp_tool(self):
        result = map_tool("mcp__github__create_issue", {"title": "bug", "body": "desc"})
        assert result == ("github", "create_issue", "create_issue")

    def test_mcp_tool_with_scope_param(self):
        result = map_tool("mcp__myserver__read_file", {"path": "/etc/config"})
        assert result == ("myserver", "read_file", "/etc/config")

    def test_aiperture_mcp_skipped(self):
        result = map_tool("mcp__aiperture__check_permission", {"tool": "shell"})
        assert result is None

    def test_aiperture_mcp_any_tool_skipped(self):
        result = map_tool("mcp__aiperture__store_artifact", {"content": "hello"})
        assert result is None

    def test_unknown_tool(self):
        result = map_tool("CustomTool", {"scope": "something"})
        assert result is not None
        assert result[0] == "unknown"
        assert result[1] == "CustomTool"

    def test_case_insensitive(self):
        result = map_tool("bash", {"command": "ls"})
        assert result == ("shell", "execute", "ls")

    def test_empty_input(self):
        result = map_tool("Bash", {})
        assert result == ("shell", "execute", "")


# --- PendingTracker tests ---


class TestPendingTracker:

    def test_add_and_resolve(self):
        tracker = PendingTracker()
        req = PendingRequest(
            tool="shell", action="execute", scope="npm test",
            session_id="s1", organization_id="default",
        )
        tracker.add("t1", req)
        assert len(tracker) == 1
        resolved = tracker.resolve("t1")
        assert resolved is req
        assert len(tracker) == 0

    def test_resolve_unknown(self):
        tracker = PendingTracker()
        assert tracker.resolve("nonexistent") is None

    def test_collect_expired(self):
        tracker = PendingTracker(timeout_seconds=0.1)
        req = PendingRequest(
            tool="shell", action="execute", scope="ls",
            session_id="s1", organization_id="default",
            created_at=time.time() - 1,  # already expired
        )
        tracker.add("t1", req)
        expired = tracker.collect_expired()
        assert len(expired) == 1
        assert expired[0] is req
        assert len(tracker) == 0

    def test_non_expired_not_collected(self):
        tracker = PendingTracker(timeout_seconds=300)
        req = PendingRequest(
            tool="shell", action="execute", scope="ls",
            session_id="s1", organization_id="default",
        )
        tracker.add("t1", req)
        expired = tracker.collect_expired()
        assert len(expired) == 0
        assert len(tracker) == 1


# --- Hook endpoint tests ---


class TestHookEndpoints:

    def _client(self):
        app = create_app()
        return TestClient(app)

    def test_permission_request_unknown_pattern_returns_empty(self):
        """When AIperture has no learned pattern, return {} for normal prompt."""
        client = self._client()
        resp = client.post("/hooks/permission-request", json={
            "tool_name": "Bash",
            "tool_input": {"command": "some-unknown-command-xyz"},
            "session_id": "test-session",
        })
        assert resp.status_code == 200
        assert resp.json() == {}

    def test_permission_request_aiperture_tool_skipped(self):
        """AIperture's own MCP tools should be skipped."""
        client = self._client()
        resp = client.post("/hooks/permission-request", json={
            "tool_name": "mcp__aiperture__check_permission",
            "tool_input": {"tool": "shell"},
            "session_id": "test-session",
        })
        assert resp.status_code == 200
        assert resp.json() == {}

    def test_post_tool_use_records_approval(self):
        """PostToolUse should record an implicit approval."""
        client = self._client()
        resp = client.post("/hooks/post-tool-use", json={
            "tool_name": "Read",
            "tool_input": {"file_path": "/src/main.py"},
            "tool_use_id": "tu_3",
            "session_id": "test-session",
        })
        assert resp.status_code == 200
        assert resp.json()["recorded"] is True

    def test_post_tool_use_aiperture_skipped(self):
        """AIperture's own MCP tools should not be recorded."""
        client = self._client()
        resp = client.post("/hooks/post-tool-use", json={
            "tool_name": "mcp__aiperture__store_artifact",
            "tool_input": {"content": "test"},
            "tool_use_id": "tu_4",
            "session_id": "test-session",
        })
        assert resp.status_code == 200
        assert resp.json()["recorded"] is False

    def test_high_risk_never_auto_approved(self):
        """HIGH/CRITICAL risk actions must never auto-approve, even with learned patterns."""
        client = self._client()
        engine = PermissionEngine()

        # Seed enough approvals for learning
        for i in range(15):
            engine.record_hook_decision(
                tool="shell", action="execute", scope="rm -rf /tmp/data",
                decision=PermissionDecision.ALLOW,
                session_id=f"seed-{i}",
                organization_id="default",
            )

        # This is HIGH risk — should return {} regardless
        resp = client.post("/hooks/permission-request", json={
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /tmp/data"},
            "session_id": "test-high-risk",
        })
        assert resp.status_code == 200
        data = resp.json()
        # Should NOT auto-approve — either {} or deny
        decision = data.get("hookSpecificOutput", {}).get("decision", {})
        assert decision.get("behavior") != "allow"

    def test_learned_pattern_auto_approves(self):
        """After enough approvals, PermissionRequest should return auto-approve."""
        client = self._client()
        engine = PermissionEngine()

        import aiperture.config
        # Lower thresholds for test
        original_min = aiperture.config.settings.permission_learning_min_decisions
        object.__setattr__(aiperture.config.settings, "permission_learning_min_decisions", 3)

        try:
            # Seed 3 approvals for a low-risk action
            for i in range(3):
                engine.record_hook_decision(
                    tool="filesystem", action="read", scope="src/*.py",
                    decision=PermissionDecision.ALLOW,
                    session_id=f"learn-{i}",
                    organization_id="default",
                )

            # Now the pattern should be auto-approved with hookSpecificOutput wrapper
            resp = client.post("/hooks/permission-request", json={
                "tool_name": "Read",
                "tool_input": {"file_path": "src/main.py"},
                "session_id": "test-auto-approve",
            })
            assert resp.status_code == 200
            data = resp.json()
            hook_output = data.get("hookSpecificOutput", {})
            assert hook_output.get("hookEventName") == "PermissionRequest"
            assert hook_output.get("decision", {}).get("behavior") == "allow"
        finally:
            object.__setattr__(
                aiperture.config.settings,
                "permission_learning_min_decisions",
                original_min,
            )

    def test_auto_approved_not_double_counted(self):
        """PostToolUse should skip recording for auto-approved actions."""
        client = self._client()
        engine = PermissionEngine()

        import aiperture.config
        original_min = aiperture.config.settings.permission_learning_min_decisions
        object.__setattr__(aiperture.config.settings, "permission_learning_min_decisions", 3)

        try:
            # Seed learning
            for i in range(3):
                engine.record_hook_decision(
                    tool="filesystem", action="read", scope="src/*.py",
                    decision=PermissionDecision.ALLOW,
                    session_id=f"learn-{i}",
                    organization_id="default",
                )

            tool_input = {"file_path": "src/main.py"}
            session_id = "test-no-double-count"

            # PermissionRequest auto-approves
            resp1 = client.post("/hooks/permission-request", json={
                "tool_name": "Read",
                "tool_input": tool_input,
                "session_id": session_id,
            })
            assert resp1.json().get("hookSpecificOutput", {}).get("decision", {}).get("behavior") == "allow"

            # PostToolUse should skip recording
            resp2 = client.post("/hooks/post-tool-use", json={
                "tool_name": "Read",
                "tool_input": tool_input,
                "tool_use_id": "tu_auto",
                "session_id": session_id,
            })
            assert resp2.json()["recorded"] is False
            assert resp2.json()["reason"] == "auto_approved"
        finally:
            object.__setattr__(
                aiperture.config.settings,
                "permission_learning_min_decisions",
                original_min,
            )

    def test_permission_request_no_tool_use_id_field(self):
        """PermissionRequest payload should work without tool_use_id."""
        client = self._client()
        # Claude Code doesn't send tool_use_id for PermissionRequest
        resp = client.post("/hooks/permission-request", json={
            "tool_name": "Bash",
            "tool_input": {"command": "echo hello"},
            "session_id": "test-no-id",
        })
        assert resp.status_code == 200


class TestRecordHookDecision:

    def test_record_hook_decision_basic(self):
        """record_hook_decision should persist without HMAC."""
        engine = PermissionEngine()
        log = engine.record_hook_decision(
            tool="filesystem",
            action="read",
            scope="src/main.py",
            decision=PermissionDecision.ALLOW,
            session_id="test-session",
            organization_id="default",
        )
        assert log.decided_by == "human:claude-code-hook"
        assert log.decision == PermissionDecision.ALLOW

    def test_record_hook_decision_caches_in_session(self):
        """Hook decisions should be cached in session memory."""
        engine = PermissionEngine()
        engine.record_hook_decision(
            tool="filesystem",
            action="read",
            scope="src/main.py",
            decision=PermissionDecision.ALLOW,
            session_id="cache-test",
            organization_id="default",
        )
        # Check session cache
        cache_key = ("default", "filesystem", "read", "src/main.py", "cache-test", "")
        cached = engine._session_cache.get(cache_key)
        assert cached == PermissionDecision.ALLOW

    def test_record_hook_decision_records_normalized_scope(self):
        """Hook decisions should also record the normalized scope."""
        engine = PermissionEngine()
        log = engine.record_hook_decision(
            tool="filesystem",
            action="read",
            scope="src/components/Button.tsx",
            decision=PermissionDecision.ALLOW,
            session_id="norm-test",
            organization_id="default",
        )
        # Normalized scope should also be cached
        norm_key = ("default", "filesystem", "read", "src/components/*.tsx", "norm-test", "")
        cached = engine._session_cache.get(norm_key)
        assert cached == PermissionDecision.ALLOW
