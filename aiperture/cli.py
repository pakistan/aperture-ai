"""AIperture CLI entry point."""

import sys

from aiperture import plugins


def main():
    plugins.load_all()
    args = sys.argv[1:]

    if not args or args[0] in ("--help", "-h"):
        print("AIperture — The permission layer for AI agents\n")  # noqa: T201
        print("Commands:")  # noqa: T201
        print("  setup-claude   Set up AIperture for Claude Code")  # noqa: T201
        print("  remove-claude  Remove AIperture from Claude Code")  # noqa: T201
        print("  serve          Run HTTP API server")  # noqa: T201
        print("  mcp-serve      Run as MCP server (stdio transport)")  # noqa: T201
        print("  init-db        Initialize the database")  # noqa: T201
        print("  configure      Interactive setup wizard")  # noqa: T201
        print("  bootstrap      Seed permission decisions from a preset")  # noqa: T201
        print("  revoke         Revoke auto-approval for a permission pattern")  # noqa: T201
        sys.exit(0)

    cmd = args[0]

    if cmd == "setup-claude":
        _setup_claude(args[1:])

    elif cmd == "remove-claude":
        _remove_claude(args[1:])

    elif cmd == "serve":
        import logging

        import uvicorn

        import aiperture.config
        from aiperture.api.app import create_app

        logging.basicConfig(
            level=getattr(logging, aiperture.config.settings.log_level.upper(), logging.INFO),
            format="%(asctime)s [aiperture] %(levelname)s %(message)s",
        )
        aiperture.config.setup_file_logging()

        app = create_app()
        settings = aiperture.config.settings
        uvicorn.run(app, host=settings.api_host, port=settings.api_port)

    elif cmd == "mcp-serve":
        from aiperture.mcp_server import serve
        serve()

    elif cmd == "init-db":
        from aiperture.db import init_db
        init_db()
        print("Database initialized.")  # noqa: T201

    elif cmd == "configure":
        _configure()

    elif cmd == "bootstrap":
        _bootstrap(args[1:])

    elif cmd == "revoke":
        _revoke(args[1:])

    # Backward compat alias
    elif cmd == "init-claude":
        _setup_claude(args[1:])

    else:
        print(f"Unknown command: {cmd}")  # noqa: T201
        sys.exit(1)


def _ensure_gitignore() -> None:
    """Ensure .gitignore contains patterns for AIperture DB files."""
    from pathlib import Path

    gitignore = Path(".gitignore")
    patterns = ["*.db", "*.db-shm", "*.db-wal", ".aiperture.env"]

    existing = ""
    if gitignore.exists():
        existing = gitignore.read_text()

    missing = [p for p in patterns if p not in existing]
    if not missing:
        return

    lines = existing.rstrip("\n")
    if lines:
        lines += "\n"
    lines += "\n# AIperture\n"
    lines += "\n".join(missing) + "\n"
    gitignore.write_text(lines)
    print(f"Added {', '.join(missing)} to .gitignore")  # noqa: T201


def _setup_claude(args: list[str]):
    """Set up AIperture as Claude Code's MCP permission layer."""
    import json
    from pathlib import Path

    from aiperture.db import init_db

    if args and args[0] in ("--help", "-h"):
        print("Usage: aiperture setup-claude [--global] [--bootstrap=PRESET]")  # noqa: T201
        print()  # noqa: T201
        print("Options:")  # noqa: T201
        print("  --global             Install to ~/.claude/.mcp.json (all projects)")  # noqa: T201
        print("  --bootstrap=PRESET   Pre-seed patterns: developer, readonly, minimal")  # noqa: T201
        print()  # noqa: T201
        print("Default: project-level .mcp.json in current directory")  # noqa: T201
        return

    global_mode = "--global" in args
    bootstrap_preset = None
    for a in args:
        if a.startswith("--bootstrap="):
            bootstrap_preset = a.split("=", 1)[1]

    # Determine MCP config path
    if global_mode:
        claude_dir = Path.home() / ".claude"
        claude_dir.mkdir(exist_ok=True)
        mcp_path = claude_dir / ".mcp.json"
    else:
        mcp_path = Path(".mcp.json")

    # Read existing config or start fresh
    if mcp_path.exists():
        try:
            config = json.loads(mcp_path.read_text())
        except (json.JSONDecodeError, OSError):
            config = {}
    else:
        config = {}

    if "mcpServers" not in config:
        config["mcpServers"] = {}

    # Check if already configured
    if "aiperture" in config["mcpServers"]:
        print(f"AIperture is already configured in {mcp_path}")  # noqa: T201
        print("Existing config left unchanged.")  # noqa: T201
    else:
        # Find the aiperture binary
        aiperture_bin = sys.executable.rsplit("/", 1)[0] + "/aiperture"
        if not Path(aiperture_bin).exists():
            aiperture_bin = "aiperture"  # fall back to PATH

        config["mcpServers"]["aiperture"] = {
            "type": "stdio",
            "command": aiperture_bin,
            "args": ["mcp-serve"],
        }
        mcp_path.write_text(json.dumps(config, indent=2) + "\n")
        print(f"Added AIperture to {mcp_path}")  # noqa: T201

    # Add mcp__aiperture__* to Claude Code's permission allow list
    if global_mode:
        settings_path = Path.home() / ".claude" / "settings.json"
    else:
        settings_dir = Path(".claude")
        settings_dir.mkdir(exist_ok=True)
        settings_path = settings_dir / "settings.json"

    mcp_allow_rule = "mcp__aiperture__*"
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
        except (json.JSONDecodeError, OSError):
            settings = {}
    else:
        settings = {}

    permissions = settings.setdefault("permissions", {})
    allow_list = permissions.setdefault("allow", [])
    if mcp_allow_rule not in allow_list:
        allow_list.append(mcp_allow_rule)
        settings_path.write_text(json.dumps(settings, indent=2) + "\n")
        print(f"Added {mcp_allow_rule} to {settings_path}")  # noqa: T201
    else:
        print(f"{mcp_allow_rule} already in {settings_path}")  # noqa: T201

    # Write hooks config to settings.json for Claude Code hook integration
    _write_hooks_config(settings, settings_path)

    # Ensure DB files are in .gitignore
    _ensure_gitignore()

    # Initialize database
    init_db()
    print("Database initialized.")  # noqa: T201

    # Bootstrap if requested
    if bootstrap_preset:
        from aiperture.permissions.presets import apply_preset

        try:
            total = apply_preset(bootstrap_preset)
            print(f"Applied '{bootstrap_preset}' preset: {total} patterns seeded.")  # noqa: T201
        except KeyError as e:
            print(f"Unknown preset: {e}")  # noqa: T201
            sys.exit(1)

    print()  # noqa: T201
    print("Done! Restart Claude Code to activate AIperture.")  # noqa: T201
    print("The MCP server handles both tools and learning hooks automatically.")  # noqa: T201
    if not bootstrap_preset:
        print("Tip: run 'aiperture setup-claude --bootstrap=developer' to pre-seed 75 safe patterns.")  # noqa: T201


def _write_hooks_config(settings: dict, settings_path) -> None:
    """Write Claude Code hook entries to settings.json.

    Merges with any existing hooks — does not overwrite.
    """
    import json

    aiperture_hooks = {
        "SessionStart": [{
            "matcher": "startup",
            "hooks": [{
                "type": "command",
                "command": "curl -sf http://localhost:8100/hooks/session-start 2>/dev/null || echo '{}'",
                "timeout": 5,
            }],
        }],
        "PermissionRequest": [{
            "matcher": "^(?!mcp__aiperture__).*",
            "hooks": [{"type": "http", "url": "http://localhost:8100/hooks/permission-request"}],
        }],
        "PostToolUse": [{
            "matcher": "^(?!mcp__aiperture__).*",
            "hooks": [{"type": "http", "url": "http://localhost:8100/hooks/post-tool-use"}],
        }],
    }

    existing_hooks = settings.get("hooks", {})
    added = False

    for event_name, new_entries in aiperture_hooks.items():
        event_hooks = existing_hooks.get(event_name, [])
        # Remove any existing AIperture hook entries first to avoid duplicates
        event_hooks = [
            entry for entry in event_hooks
            if not any(
                "aiperture" in h.get("url", "") or "aiperture" in h.get("command", "")
                for h in entry.get("hooks", [])
            )
        ]
        event_hooks.extend(new_entries)
        added = True
        existing_hooks[event_name] = event_hooks

    settings["hooks"] = existing_hooks
    settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    if added:
        print(f"Added Claude Code hooks to {settings_path}")  # noqa: T201
    else:
        print(f"Claude Code hooks already in {settings_path}")  # noqa: T201


def _remove_claude(args: list[str]):
    """Remove AIperture from Claude Code's MCP config."""
    import json
    from pathlib import Path

    if args and args[0] in ("--help", "-h"):
        print("Usage: aiperture remove-claude [--global]")  # noqa: T201
        print()  # noqa: T201
        print("Options:")  # noqa: T201
        print("  --global  Remove from ~/.claude/.mcp.json instead of project .mcp.json")  # noqa: T201
        print()  # noqa: T201
        print("This only removes the MCP config entry. Your database and learned")  # noqa: T201
        print("patterns are preserved — run setup-claude to reconnect anytime.")  # noqa: T201
        return

    global_mode = "--global" in args

    if global_mode:
        mcp_path = Path.home() / ".claude" / ".mcp.json"
    else:
        mcp_path = Path(".mcp.json")

    if not mcp_path.exists():
        print(f"No MCP config found at {mcp_path}")  # noqa: T201
        return

    try:
        config = json.loads(mcp_path.read_text())
    except (json.JSONDecodeError, OSError):
        print(f"Could not read {mcp_path}")  # noqa: T201
        sys.exit(1)

    servers = config.get("mcpServers", {})
    if "aiperture" not in servers:
        print(f"AIperture is not configured in {mcp_path}")  # noqa: T201
        return

    del servers["aiperture"]

    # If no servers left and no other keys, remove the file
    if not servers and list(config.keys()) == ["mcpServers"]:
        mcp_path.unlink()
        print(f"Removed {mcp_path} (no other MCP servers configured)")  # noqa: T201
    else:
        mcp_path.write_text(json.dumps(config, indent=2) + "\n")
        print(f"Removed AIperture from {mcp_path}")  # noqa: T201

    # Remove mcp__aiperture__* from Claude Code's permission allow list + hooks
    if global_mode:
        settings_path = Path.home() / ".claude" / "settings.json"
    else:
        settings_path = Path(".claude") / "settings.json"

    mcp_allow_rule = "mcp__aiperture__*"
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
            allow_list = settings.get("permissions", {}).get("allow", [])
            if mcp_allow_rule in allow_list:
                allow_list.remove(mcp_allow_rule)
                print(f"Removed {mcp_allow_rule} from {settings_path}")  # noqa: T201

            # Remove AIperture hook entries
            hooks = settings.get("hooks", {})
            hooks_removed = False
            for event_name in ("SessionStart", "PermissionRequest", "PostToolUse"):
                if event_name in hooks:
                    original_len = len(hooks[event_name])
                    hooks[event_name] = [
                        entry for entry in hooks[event_name]
                        if not any(
                            "aiperture" in h.get("url", "") or "aiperture" in h.get("command", "")
                            for h in entry.get("hooks", [])
                        )
                    ]
                    if len(hooks[event_name]) < original_len:
                        hooks_removed = True
                    if not hooks[event_name]:
                        del hooks[event_name]
            if not hooks:
                settings.pop("hooks", None)
            if hooks_removed:
                print(f"Removed AIperture hooks from {settings_path}")  # noqa: T201

            settings_path.write_text(json.dumps(settings, indent=2) + "\n")
        except (json.JSONDecodeError, OSError):
            pass  # best-effort cleanup

    print("Your database and learned patterns are preserved.")  # noqa: T201
    print("Run 'aiperture setup-claude' to reconnect anytime.")  # noqa: T201


def _bootstrap(args: list[str]):
    """Apply a bootstrap preset to seed permission decisions."""
    from aiperture.db import init_db
    from aiperture.permissions.presets import apply_preset, get_preset_names

    init_db()

    if not args or args[0] in ("--help", "-h"):
        names = get_preset_names()
        print("Usage: aiperture bootstrap <preset_name>")  # noqa: T201
        print(f"\nAvailable presets: {', '.join(names)}")  # noqa: T201
        print("\n  developer  — filesystem reads, git, test runners, linters")  # noqa: T201
        print("  readonly   — filesystem reads and safe shell commands only")  # noqa: T201
        print("  minimal    — nothing pre-approved (fresh start)")  # noqa: T201
        return

    preset_name = args[0]
    org_id = "default"
    if len(args) > 1 and args[1].startswith("--org="):
        org_id = args[1].split("=", 1)[1]

    try:
        total = apply_preset(preset_name, organization_id=org_id)
        print(f"Applied '{preset_name}' preset: {total} decisions seeded.")  # noqa: T201
        print("These patterns will now auto-approve immediately.")  # noqa: T201
    except KeyError as e:
        print(f"Error: {e}")  # noqa: T201
        sys.exit(1)


def _revoke(args: list[str]):
    """Revoke auto-approval for a permission pattern."""
    from aiperture.db import init_db
    from aiperture.permissions.engine import PermissionEngine

    if len(args) < 3 or args[0] in ("--help", "-h"):
        print("Usage: aiperture revoke <tool> <action> <scope> [--org=ORG_ID]")  # noqa: T201
        print("\nExample: aiperture revoke shell execute 'rm -rf*'")  # noqa: T201
        return

    init_db()
    tool, action, scope = args[0], args[1], args[2]
    org_id = "default"
    for a in args[3:]:
        if a.startswith("--org="):
            org_id = a.split("=", 1)[1]

    engine = PermissionEngine()
    count = engine.revoke_pattern(tool, action, scope, revoked_by="cli", organization_id=org_id)
    print(f"Revoked {count} decision(s) for {tool}.{action} on {scope}")  # noqa: T201


def _configure(input_fn=None, env_file_path=None):
    """Interactive setup wizard for tunable settings.

    Args:
        input_fn: Override for input() — used in tests.
        env_file_path: Override for .aiperture.env path — used in tests.
    """
    import aiperture.config
    from aiperture.config import Settings

    _input = input_fn or input
    env_path = env_file_path or ".aiperture.env"

    print("\nAIperture Configuration Wizard")  # noqa: T201
    print("=" * 40)  # noqa: T201
    print("Press Enter to keep the current value shown in [brackets].\n")  # noqa: T201

    updates: dict = {}
    field_types = {
        name: field.annotation
        for name, field in Settings.model_fields.items()
        if name in Settings.TUNABLE_FIELDS
    }

    for field in sorted(Settings.TUNABLE_FIELDS):
        current = getattr(aiperture.config.settings, field)
        desc = Settings.TUNABLE_DESCRIPTIONS.get(field, "")
        ftype = field_types.get(field)

        prompt = f"  {field} — {desc}\n    [{current}]: "
        raw = _input(prompt).strip()

        if not raw:
            continue  # keep current value

        try:
            if ftype is bool:
                value = raw.lower() in ("true", "1", "yes", "on")
            elif ftype is int:
                value = int(raw)
            elif ftype is float:
                value = float(raw)
            else:
                value = raw
            updates[field] = value
        except (ValueError, TypeError) as e:
            print(f"    Invalid value for {field}: {e}. Keeping current.")  # noqa: T201

    if updates:
        try:
            aiperture.config.update_settings(updates, env_file_path=env_path)
            print(f"\nSaved {len(updates)} setting(s) to {env_path}")  # noqa: T201
        except ValueError as e:
            print(f"\nConfiguration error: {e}")  # noqa: T201
            sys.exit(1)
    else:
        print("\nNo changes made.")  # noqa: T201

    # Offer to init-db
    init = _input("\nInitialize database now? [Y/n]: ").strip().lower()
    if init in ("", "y", "yes"):
        from aiperture.db import init_db
        init_db()
        print("Database initialized.")  # noqa: T201

    print("\nDone! Run 'aiperture serve' to start the API server.")  # noqa: T201


if __name__ == "__main__":
    main()
