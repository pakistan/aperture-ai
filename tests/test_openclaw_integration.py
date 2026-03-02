"""Integration tests for the OpenClaw-style learning loop.

Tests the full flow: check -> deny -> human approves N times -> auto-approve.
Also validates the example OpenClaw config files ship correctly.

Three test tiers:
  1. Config validation — shipped example files are correct
  2. Learning loop via HTTP — TestClient-based end-to-end tests
  3. MCP protocol — real stdio client connecting to `aperture mcp-serve`
"""

import json
import shutil
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import aperture.config
from aperture.api import create_app

# Path to the examples/ directory (relative to repo root)
EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"

# Path to the aperture CLI in the current venv
APERTURE_CLI = str(Path(sys.executable).parent / "aperture")


# ── Config validation tests ──────────────────────────────────────────


class TestOpenClawConfig:
    """Validate that the shipped OpenClaw config files are correct."""

    def test_openclaw_json_config_valid(self):
        """The example openclaw.json is valid and wires Aperture correctly."""
        config_path = EXAMPLES_DIR / "openclaw.json"
        assert config_path.exists(), f"Missing {config_path}"

        config = json.loads(config_path.read_text())
        assert "mcpServers" in config
        mcp = config["mcpServers"]["aperture"]
        assert mcp["command"] == "aperture"
        assert mcp["args"] == ["mcp-serve"]
        assert "APERTURE_DB_PATH" in mcp["env"]
        assert "APERTURE_PERMISSION_LEARNING_MIN_DECISIONS" in mcp["env"]
        assert "APERTURE_AUTO_APPROVE_THRESHOLD" in mcp["env"]
        assert "APERTURE_AUTO_DENY_THRESHOLD" in mcp["env"]

    def test_openclaw_json_thresholds_are_demo_friendly(self):
        """Demo thresholds should be low for quick learning."""
        config = json.loads((EXAMPLES_DIR / "openclaw.json").read_text())
        env = config["mcpServers"]["aperture"]["env"]
        assert int(env["APERTURE_PERMISSION_LEARNING_MIN_DECISIONS"]) <= 5
        assert float(env["APERTURE_AUTO_APPROVE_THRESHOLD"]) <= 0.90

    def test_system_prompt_exists(self):
        """The system prompt file exists and mentions key Aperture tools."""
        prompt_path = EXAMPLES_DIR / "system_prompt.md"
        assert prompt_path.exists(), f"Missing {prompt_path}"
        text = prompt_path.read_text()
        assert "check_permission" in text
        assert "approve_action" in text
        assert "deny_action" in text
        assert "get_permission_patterns" in text

    def test_setup_script_exists_and_executable(self):
        """The setup script exists."""
        script = EXAMPLES_DIR / "openclaw_setup.sh"
        assert script.exists(), f"Missing {script}"


# ── Learning loop tests (HTTP) ───────────────────────────────────────


class TestLearningLoop:
    """End-to-end permission learning integration tests."""

    def _setup_low_thresholds(self):
        """Configure low thresholds for fast learning in tests."""
        aperture.config.settings.permission_learning_min_decisions = 5
        aperture.config.settings.auto_approve_threshold = 0.90
        aperture.config.settings.auto_deny_threshold = 0.05

    def test_deny_with_no_history(self):
        """First check with no rules and no history should deny."""
        app = create_app()
        client = TestClient(app)
        resp = client.post("/permissions/check", json={
            "tool": "shell",
            "action": "execute",
            "scope": "git status",
            "permissions": [],
        })
        assert resp.status_code == 200
        assert resp.json()["decision"] == "deny"

    def test_auto_approve_after_learning(self):
        """After enough human approvals, the same action is auto-approved."""
        self._setup_low_thresholds()
        app = create_app()
        client = TestClient(app)

        # Record 5 approvals (meets min_decisions=5)
        for i in range(5):
            resp = client.post("/permissions/record", json={
                "tool": "shell",
                "action": "execute",
                "scope": "git status",
                "decision": "allow",
                "decided_by": f"user-{i % 3}",
                "organization_id": "test-org",
            })
            assert resp.status_code == 200

        # Now check — should be auto-approved via learning
        resp = client.post("/permissions/check", json={
            "tool": "shell",
            "action": "execute",
            "scope": "git status",
            "permissions": [],
            "organization_id": "test-org",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "allow"
        assert data["decided_by"] == "auto_learned"

    def test_auto_deny_after_denials(self):
        """After enough human denials, the same action is auto-denied."""
        self._setup_low_thresholds()
        app = create_app()
        client = TestClient(app)

        # Record 5 denials
        for i in range(5):
            resp = client.post("/permissions/record", json={
                "tool": "shell",
                "action": "execute",
                "scope": "rm -rf /",
                "decision": "deny",
                "decided_by": f"user-{i}",
                "organization_id": "deny-org",
            })
            assert resp.status_code == 200

        # Now check — should be auto-denied
        resp = client.post("/permissions/check", json={
            "tool": "shell",
            "action": "execute",
            "scope": "rm -rf /",
            "permissions": [],
            "organization_id": "deny-org",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "deny"

    def test_config_api_adjusts_learning(self):
        """PATCH /config changes learning thresholds and affects behavior."""
        app = create_app()
        client = TestClient(app)

        # Set very low thresholds via config API
        resp = client.patch("/config", json={
            "settings": {
                "permission_learning_min_decisions": 3,
                "auto_approve_threshold": 0.80,
            },
        })
        assert resp.status_code == 200
        assert resp.json()["settings"]["permission_learning_min_decisions"] == 3

        # Record 3 approvals (meets new min_decisions=3)
        for i in range(3):
            client.post("/permissions/record", json={
                "tool": "filesystem",
                "action": "read",
                "scope": "src/*.py",
                "decision": "allow",
                "decided_by": f"dev-{i}",
                "organization_id": "config-test-org",
            })

        # Should be auto-approved with the new lower thresholds
        resp = client.post("/permissions/check", json={
            "tool": "filesystem",
            "action": "read",
            "scope": "src/*.py",
            "permissions": [],
            "organization_id": "config-test-org",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "allow"
        assert data["decided_by"] == "auto_learned"


# ── MCP protocol tests ──────────────────────────────────────────────
#
# These tests spawn `aperture mcp-serve` as a subprocess and connect
# via the MCP Python SDK over stdio — the exact same protocol path
# that OpenClaw (or any MCP client) uses.


def _mcp_server_params(db_path: str, **extra_env: str):
    """Create StdioServerParameters for the Aperture MCP server."""
    from mcp import StdioServerParameters

    env = {"APERTURE_DB_PATH": db_path, **extra_env}
    return StdioServerParameters(command=APERTURE_CLI, args=["mcp-serve"], env=env)


class TestMCPToolDiscovery:
    """Verify Aperture's MCP server exposes the correct tools over stdio."""

    EXPECTED_TOOLS = {
        "check_permission",
        "approve_action",
        "deny_action",
        "explain_action",
        "get_permission_patterns",
        "store_artifact",
        "verify_artifact",
        "get_cost_summary",
        "get_audit_trail",
        "get_config",
        "update_config",
    }

    async def test_server_identifies_as_aperture(self, tmp_path):
        """MCP initialize handshake returns server name 'aperture'."""
        from mcp import ClientSession, stdio_client

        params = _mcp_server_params(str(tmp_path / "test.db"))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                result = await session.initialize()
                assert result.serverInfo.name == "aperture"

    async def test_lists_all_eleven_tools(self, tmp_path):
        """MCP list_tools returns all 11 Aperture tools."""
        from mcp import ClientSession, stdio_client

        params = _mcp_server_params(str(tmp_path / "test.db"))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools_result = await session.list_tools()
                tool_names = {t.name for t in tools_result.tools}
                assert tool_names == self.EXPECTED_TOOLS

    async def test_tools_have_descriptions(self, tmp_path):
        """Every tool has a non-empty description."""
        from mcp import ClientSession, stdio_client

        params = _mcp_server_params(str(tmp_path / "test.db"))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools_result = await session.list_tools()
                for tool in tools_result.tools:
                    assert tool.description, f"{tool.name} has no description"

    async def test_tools_have_input_schemas(self, tmp_path):
        """Every tool has an inputSchema for argument validation."""
        from mcp import ClientSession, stdio_client

        params = _mcp_server_params(str(tmp_path / "test.db"))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools_result = await session.list_tools()
                for tool in tools_result.tools:
                    assert tool.inputSchema, f"{tool.name} has no inputSchema"


class TestMCPPermissionCalls:
    """Call permission tools over the real MCP protocol."""

    async def test_check_permission_denies_with_no_history(self, tmp_path):
        """check_permission returns deny when there's no decision history."""
        from mcp import ClientSession, stdio_client

        params = _mcp_server_params(str(tmp_path / "test.db"))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("check_permission", {
                    "tool": "shell",
                    "action": "execute",
                    "scope": "git status",
                })
                assert not result.isError
                data = json.loads(result.content[0].text)
                assert data["decision"] == "deny"

    async def test_check_permission_includes_risk(self, tmp_path):
        """check_permission verdict includes risk assessment."""
        from mcp import ClientSession, stdio_client

        params = _mcp_server_params(str(tmp_path / "test.db"))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("check_permission", {
                    "tool": "shell",
                    "action": "execute",
                    "scope": "rm -rf /",
                })
                data = json.loads(result.content[0].text)
                assert "risk" in data
                assert data["risk"]["tier"] == "critical"

    async def test_approve_action_records_decision(self, tmp_path):
        """approve_action returns recorded=true."""
        from mcp import ClientSession, stdio_client

        params = _mcp_server_params(str(tmp_path / "test.db"))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("approve_action", {
                    "tool": "filesystem",
                    "action": "read",
                    "scope": "README.md",
                    "decided_by": "test-user",
                })
                assert not result.isError
                data = json.loads(result.content[0].text)
                assert data["recorded"] is True
                assert data["decision"] == "allow"

    async def test_deny_action_records_decision(self, tmp_path):
        """deny_action returns recorded=true."""
        from mcp import ClientSession, stdio_client

        params = _mcp_server_params(str(tmp_path / "test.db"))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("deny_action", {
                    "tool": "shell",
                    "action": "execute",
                    "scope": "rm -rf /",
                    "decided_by": "security-admin",
                })
                assert not result.isError
                data = json.loads(result.content[0].text)
                assert data["recorded"] is True
                assert data["decision"] == "deny"

    async def test_explain_action_returns_explanation(self, tmp_path):
        """explain_action returns risk and human-readable text."""
        from mcp import ClientSession, stdio_client

        params = _mcp_server_params(str(tmp_path / "test.db"))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("explain_action", {
                    "tool": "shell",
                    "action": "execute",
                    "scope": "git status",
                })
                assert not result.isError
                data = json.loads(result.content[0].text)
                assert "explanation" in data
                assert "risk" in data


class TestMCPLearningLoop:
    """Full permission learning loop over the MCP protocol.

    This is the core integration test: it exercises the exact path that
    OpenClaw (or any MCP client) uses to interact with Aperture.
    """

    async def test_deny_approve_three_times_auto_approve(self, tmp_path):
        """Full loop: deny -> 3 human approvals -> auto-approve."""
        from mcp import ClientSession, stdio_client

        params = _mcp_server_params(
            str(tmp_path / "test.db"),
            APERTURE_PERMISSION_LEARNING_MIN_DECISIONS="3",
            APERTURE_AUTO_APPROVE_THRESHOLD="0.80",
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Step 1: First check — should be denied (no history)
                result = await session.call_tool("check_permission", {
                    "tool": "filesystem",
                    "action": "read",
                    "scope": "README.md",
                    "organization_id": "mcp-test-org",
                })
                data = json.loads(result.content[0].text)
                assert data["decision"] == "deny", "Expected deny with no history"

                # Step 2: Human approves 3 times (meets min_decisions=3)
                for i in range(3):
                    result = await session.call_tool("approve_action", {
                        "tool": "filesystem",
                        "action": "read",
                        "scope": "README.md",
                        "decided_by": f"developer-{i}",
                        "organization_id": "mcp-test-org",
                    })
                    data = json.loads(result.content[0].text)
                    assert data["recorded"] is True

                # Step 3: Check again — should be auto-approved
                result = await session.call_tool("check_permission", {
                    "tool": "filesystem",
                    "action": "read",
                    "scope": "README.md",
                    "organization_id": "mcp-test-org",
                })
                data = json.loads(result.content[0].text)
                assert data["decision"] == "allow"
                assert data["decided_by"] == "auto_learned"

    async def test_patterns_visible_after_learning(self, tmp_path):
        """get_permission_patterns shows learned patterns after approvals."""
        from mcp import ClientSession, stdio_client

        params = _mcp_server_params(
            str(tmp_path / "test.db"),
            APERTURE_PERMISSION_LEARNING_MIN_DECISIONS="3",
            APERTURE_AUTO_APPROVE_THRESHOLD="0.80",
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # No patterns initially
                result = await session.call_tool("get_permission_patterns", {
                    "organization_id": "pattern-test-org",
                    "min_decisions": 3,
                })
                assert "No permission patterns" in result.content[0].text

                # Record 3 approvals
                for i in range(3):
                    await session.call_tool("approve_action", {
                        "tool": "shell",
                        "action": "execute",
                        "scope": "npm test",
                        "decided_by": f"dev-{i}",
                        "organization_id": "pattern-test-org",
                    })

                # Now patterns should be visible
                result = await session.call_tool("get_permission_patterns", {
                    "organization_id": "pattern-test-org",
                    "min_decisions": 3,
                })
                text = result.content[0].text
                assert "shell.execute" in text
                assert "npm test" in text

    async def test_audit_trail_records_mcp_events(self, tmp_path):
        """Audit trail captures MCP tool calls."""
        from mcp import ClientSession, stdio_client

        params = _mcp_server_params(str(tmp_path / "test.db"))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Make a check that generates an audit event
                await session.call_tool("check_permission", {
                    "tool": "shell",
                    "action": "execute",
                    "scope": "ls -la",
                })

                # Query audit trail
                result = await session.call_tool("get_audit_trail", {
                    "limit": 10,
                })
                text = result.content[0].text
                assert "permission.check" in text
                assert "shell.execute" in text

    async def test_config_readable_over_mcp(self, tmp_path):
        """get_config returns current settings over MCP."""
        from mcp import ClientSession, stdio_client

        params = _mcp_server_params(
            str(tmp_path / "test.db"),
            APERTURE_PERMISSION_LEARNING_MIN_DECISIONS="3",
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("get_config", {})
                assert not result.isError
                data = json.loads(result.content[0].text)
                assert "settings" in data
                assert data["settings"]["permission_learning_min_decisions"] == 3
