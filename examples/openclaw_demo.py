#!/usr/bin/env python3
"""OpenClaw + Aperture Demo — Permission learning loop in action.

Two modes:
  1. **Real mode** — If OpenClaw (ClawDBot) is installed, creates an isolated
     workspace, spawns OpenClaw with Aperture as its MCP server, and walks
     through a scripted conversation showing deny -> approve -> auto-approve.
  2. **Simulated mode** — Falls back to FastAPI TestClient if OpenClaw isn't
     available. Shows the exact same learning loop without a real agent runtime.

Usage:
    python examples/openclaw_demo.py          # auto-detect
    python examples/openclaw_demo.py --sim    # force simulated mode
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


# ── Utility ──────────────────────────────────────────────────────────


def _header(text: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {text}")
    print(f"{'─' * 60}")


# ── Real OpenClaw Demo ──────────────────────────────────────────────


def run_real_openclaw_demo() -> None:
    """Set up an isolated workspace and launch OpenClaw with Aperture MCP."""

    _header("Aperture + OpenClaw (Real Agent) Demo")
    print("  This demo creates a temporary workspace, wires Aperture as")
    print("  OpenClaw's MCP permission server, and runs a scripted session.\n")

    examples_dir = Path(__file__).resolve().parent

    with tempfile.TemporaryDirectory(prefix="aperture-openclaw-") as tmp:
        workspace = Path(tmp)

        # 1. Copy config files into the isolated workspace
        print("[1/6] Setting up isolated workspace ...")
        shutil.copy(examples_dir / "openclaw.json", workspace / "openclaw.json")
        shutil.copy(examples_dir / "system_prompt.md", workspace / "system_prompt.md")

        # Create a dummy file for the agent to read
        (workspace / "README.md").write_text(
            "# Demo Project\n\n"
            "This is a sample project for the Aperture permission learning demo.\n"
        )

        # 2. Patch the config to use the workspace DB path
        config_path = workspace / "openclaw.json"
        config = json.loads(config_path.read_text())
        config["mcpServers"]["aperture"]["env"]["APERTURE_DB_PATH"] = str(
            workspace / "aperture.db"
        )
        config_path.write_text(json.dumps(config, indent=2))

        # 3. Initialize Aperture DB
        print("[2/6] Initializing Aperture database ...")
        env = {**os.environ, "APERTURE_DB_PATH": str(workspace / "aperture.db")}
        subprocess.run(
            ["aperture", "init-db"],
            env=env,
            check=True,
            capture_output=True,
        )
        print("  Database created at", workspace / "aperture.db")

        # 4. Print instructions for interactive use
        print("\n[3/6] Workspace ready at:", workspace)
        print("\n  To run interactively:")
        print(f"    cd {workspace}")
        print("    openclaw chat\n")

        # 5. Attempt scripted conversation via openclaw CLI
        print("[4/6] Attempting scripted OpenClaw conversation ...")
        print("  (Sending test messages to verify Aperture MCP wiring)\n")

        # Use `openclaw run` for non-interactive scripted execution
        # If `openclaw run` isn't available, show the user how to do it manually
        try:
            result = subprocess.run(
                [
                    "openclaw", "run",
                    "--config", str(config_path),
                    "--system-prompt", (workspace / "system_prompt.md").read_text(),
                    "--message", "Read the file README.md",
                ],
                cwd=str(workspace),
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode == 0:
                print("  OpenClaw response:")
                for line in result.stdout.strip().splitlines():
                    print(f"    {line}")
            else:
                print("  OpenClaw exited with code", result.returncode)
                if result.stderr:
                    print("  stderr:", result.stderr[:500])
                print("\n  The `openclaw run` command may not be available.")
                print("  You can run the demo interactively instead:")
                print(f"    cd {workspace} && openclaw chat")
        except FileNotFoundError:
            print("  Could not find `openclaw run`. Use interactive mode:")
            print(f"    cd {workspace} && openclaw chat")
        except subprocess.TimeoutExpired:
            print("  Timed out waiting for OpenClaw. Use interactive mode:")
            print(f"    cd {workspace} && openclaw chat")

        # 6. Show the Aperture audit trail (if anything was recorded)
        print("\n[5/6] Checking Aperture audit trail ...")
        try:
            from aperture.db import init_db, reset_engine
            from aperture.stores.audit_store import AuditStore

            import aperture.config
            from aperture.config import Settings

            aperture.config.settings = Settings(
                db_path=str(workspace / "aperture.db"),
            )
            reset_engine()

            audit = AuditStore()
            events = audit.list_events(limit=20)
            if events:
                print(f"  {len(events)} audit events recorded:")
                for e in events:
                    print(f"    [{e.event_type}] {e.summary}")
            else:
                print("  No events yet — run the demo interactively to generate them.")
        except Exception as e:
            print(f"  Could not read audit trail: {e}")

        print("\n[6/6] Demo complete!")
        print("  The temporary workspace will be cleaned up automatically.")


# ── Simulated Demo (fallback) ───────────────────────────────────────


def run_simulated_demo() -> None:
    """Run the learning loop demo using FastAPI TestClient — no external deps."""

    _header("Aperture Demo: Permission Learning Loop (Simulated)")
    print("  OpenClaw not installed — using in-process simulation.")
    print("  Install OpenClaw for the real agent demo: npm install -g openclaw@latest\n")

    with tempfile.TemporaryDirectory() as tmp:
        import aperture.config
        from aperture.config import Settings
        from aperture.db.engine import init_db, reset_engine

        aperture.config.settings = Settings(
            db_path=str(Path(tmp) / "demo.db"),
            artifact_storage_dir=str(Path(tmp) / "artifacts"),
            # Low thresholds for quick demo
            permission_learning_min_decisions=5,
            auto_approve_threshold=0.90,
        )
        reset_engine()
        init_db()

        from fastapi.testclient import TestClient

        from aperture.api.app import create_app

        app = create_app()
        client = TestClient(app)

        # --- Step 1: Agent asks to run `git status` ---
        print("[Step 1] Agent asks: can I run `git status`?")
        resp = client.post("/permissions/check", json={
            "tool": "shell",
            "action": "execute",
            "scope": "git status",
            "permissions": [],
        })
        verdict = resp.json()
        print(f"  Decision: {verdict['decision']}")
        print(f"  Risk: {verdict['risk']['tier']} (score: {verdict['risk']['score']:.2f})")
        print(f"  Explanation: {verdict.get('explanation', 'N/A')}")
        assert verdict["decision"] == "deny", "Expected deny with no history"

        # --- Step 2: Human approves `git status` x5 ---
        print(f"\n[Step 2] Human approves `git status` 5 times ...")
        for i in range(5):
            resp = client.post("/permissions/record", json={
                "tool": "shell",
                "action": "execute",
                "scope": "git status",
                "decision": "allow",
                "decided_by": f"developer-{i % 2 + 1}",
                "organization_id": "demo-org",
            })
            assert resp.status_code == 200
            print(f"  Approval {i + 1}/5 recorded (by developer-{i % 2 + 1})")

        # --- Step 3: Check learned patterns ---
        print("\n[Step 3] Checking learned patterns ...")
        resp = client.get("/permissions/patterns?min_decisions=5&organization_id=demo-org")
        patterns = resp.json()
        print(f"  Patterns found: {patterns['count']}")
        if patterns["count"] > 0:
            p = patterns["patterns"][0]
            print(f"  Pattern: {p['tool']}.{p['action']} on '{p['scope']}'")
            print(f"  Approval rate: {p['approval_rate']:.0%}")
            print(f"  Recommendation: {p['recommendation']}")

        # --- Step 4: Agent asks again — should be auto-approved ---
        print("\n[Step 4] Agent asks again: can I run `git status`?")
        resp = client.post("/permissions/check", json={
            "tool": "shell",
            "action": "execute",
            "scope": "git status",
            "permissions": [],
            "organization_id": "demo-org",
        })
        verdict = resp.json()
        print(f"  Decision: {verdict['decision']}")
        decided_by = verdict.get("decided_by", "unknown")
        print(f"  Decided by: {decided_by}")

        if verdict["decision"] == "allow" and decided_by == "auto_learned":
            print("  AUTO-APPROVED! Aperture learned from human decisions.")
        else:
            print("  (Pattern detected but may need more decisions or different thresholds)")

        # --- Step 5: Show audit trail ---
        print("\n[Step 5] Audit trail:")
        resp = client.get("/audit/events?limit=10")
        events = resp.json()
        for event in events.get("events", []):
            print(f"  [{event['event_type']}] {event['summary']}")

        # --- Step 6: Show config ---
        print("\n[Step 6] Current configuration:")
        resp = client.get("/config")
        config = resp.json()
        for key, value in sorted(config["settings"].items()):
            desc = config["descriptions"].get(key, "")
            print(f"  {key} = {value}  ({desc})")

        _header("Demo complete!")
        print("  Aperture learned to auto-approve `git status`")
        print("  after 5 human approvals with a 90% threshold.\n")


# ── Entry Point ──────────────────────────────────────────────────────


def main() -> None:
    force_sim = "--sim" in sys.argv

    if not force_sim and shutil.which("openclaw"):
        run_real_openclaw_demo()
    else:
        run_simulated_demo()


if __name__ == "__main__":
    main()
