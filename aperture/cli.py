"""Aperture CLI entry point."""

import sys


def main():
    args = sys.argv[1:]

    if not args or args[0] in ("--help", "-h"):
        print("Aperture — The permission layer for AI agents\n")  # noqa: T201
        print("Commands:")  # noqa: T201
        print("  mcp-serve    Run as MCP server (stdio transport)")  # noqa: T201
        print("  serve        Run HTTP API server")  # noqa: T201
        print("  init-db      Initialize the database")  # noqa: T201
        print("  configure    Interactive setup wizard")  # noqa: T201
        sys.exit(0)

    cmd = args[0]

    if cmd == "mcp-serve":
        from aperture.mcp_server import serve
        serve()

    elif cmd == "serve":
        import uvicorn
        import aperture.config
        from aperture.api.app import create_app

        app = create_app()
        settings = aperture.config.settings
        uvicorn.run(app, host=settings.api_host, port=settings.api_port)

    elif cmd == "init-db":
        from aperture.db import init_db
        init_db()
        print("Database initialized.")  # noqa: T201

    elif cmd == "configure":
        _configure()

    else:
        print(f"Unknown command: {cmd}")  # noqa: T201
        sys.exit(1)


def _configure(input_fn=None, env_file_path=None):
    """Interactive setup wizard for tunable settings.

    Args:
        input_fn: Override for input() — used in tests.
        env_file_path: Override for .aperture.env path — used in tests.
    """
    import aperture.config
    from aperture.config import Settings

    _input = input_fn or input
    env_path = env_file_path or ".aperture.env"

    print("\nAperture Configuration Wizard")  # noqa: T201
    print("=" * 40)  # noqa: T201
    print("Press Enter to keep the current value shown in [brackets].\n")  # noqa: T201

    updates: dict = {}
    field_types = {
        name: field.annotation
        for name, field in Settings.model_fields.items()
        if name in Settings.TUNABLE_FIELDS
    }

    for field in sorted(Settings.TUNABLE_FIELDS):
        current = getattr(aperture.config.settings, field)
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
            aperture.config.update_settings(updates, env_file_path=env_path)
            print(f"\nSaved {len(updates)} setting(s) to {env_path}")  # noqa: T201
        except ValueError as e:
            print(f"\nConfiguration error: {e}")  # noqa: T201
            sys.exit(1)
    else:
        print("\nNo changes made.")  # noqa: T201

    # Offer to init-db
    init = _input("\nInitialize database now? [Y/n]: ").strip().lower()
    if init in ("", "y", "yes"):
        from aperture.db import init_db
        init_db()
        print("Database initialized.")  # noqa: T201

    print("\nDone! Run 'aperture serve' to start the API server.")  # noqa: T201


if __name__ == "__main__":
    main()
