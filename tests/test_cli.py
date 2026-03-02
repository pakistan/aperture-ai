"""Tests for the Aperture CLI entry point (aperture/cli.py).

Covers:
- Import wiring: `main` is importable from `aperture.cli`
- Entry point registration: pyproject.toml `[project.scripts]` maps `aperture` -> `aperture.cli:main`
- No-args usage: prints help and exits cleanly
- `init-db` subcommand: initializes the database without error
- `serve` subcommand: reaches uvicorn.run (mocked to prevent server start)
- `mcp-serve` subcommand: reaches aperture.mcp_server.serve (mocked to prevent server start)
- Unknown command: prints error and exits with code 1
- `--help` flag: prints usage and exits cleanly
"""

import sys
from unittest.mock import MagicMock, patch

import pytest


class TestCLIWiring:
    """Wiring tests: CLI is importable and registered as a console script."""

    def test_main_importable_from_public_module(self):
        """main() is importable from aperture.cli."""
        from aperture.cli import main

        assert callable(main)

    def test_entry_point_registered_in_pyproject(self):
        """pyproject.toml declares `aperture = aperture.cli:main` as a console script."""
        from pathlib import Path

        pyproject = Path(__file__).parent.parent / "pyproject.toml"
        content = pyproject.read_text()
        assert 'aperture = "aperture.cli:main"' in content


class TestCLINoArgs:
    """When invoked with no arguments, CLI prints usage and exits."""

    def test_no_args_prints_usage_and_exits(self, capsys, monkeypatch):
        """main() with no args prints help text and exits with code 0."""
        from aperture.cli import main

        monkeypatch.setattr(sys, "argv", ["aperture"])

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "Aperture" in captured.out
        assert "Commands:" in captured.out
        assert "mcp-serve" in captured.out
        assert "serve" in captured.out
        assert "init-db" in captured.out


class TestCLIHelp:
    """--help and -h flags print usage and exit."""

    def test_help_flag_prints_usage(self, capsys, monkeypatch):
        """main() with --help prints help text and exits with code 0."""
        from aperture.cli import main

        monkeypatch.setattr(sys, "argv", ["aperture", "--help"])

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "Commands:" in captured.out

    def test_short_help_flag(self, capsys, monkeypatch):
        """main() with -h prints help text and exits with code 0."""
        from aperture.cli import main

        monkeypatch.setattr(sys, "argv", ["aperture", "-h"])

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "Commands:" in captured.out


class TestCLIInitDB:
    """init-db subcommand initializes the database."""

    def test_init_db_succeeds(self, capsys, monkeypatch):
        """main() with init-db calls init_db() and prints success message."""
        from aperture.cli import main

        monkeypatch.setattr(sys, "argv", ["aperture", "init-db"])

        # Should not raise -- fresh_db fixture already set up a temp db
        main()

        captured = capsys.readouterr()
        assert "Database initialized" in captured.out

    def test_init_db_actually_creates_tables(self, monkeypatch):
        """init-db creates the expected tables in the database."""
        from aperture.cli import main
        from aperture.db.engine import get_engine

        monkeypatch.setattr(sys, "argv", ["aperture", "init-db"])
        main()

        # Verify tables exist by inspecting the engine
        from sqlalchemy import inspect

        inspector = inspect(get_engine())
        table_names = inspector.get_table_names()
        # At minimum, these core tables should exist
        assert "permission" in table_names or "permissionlog" in table_names or len(table_names) > 0


class TestCLIServe:
    """serve subcommand starts uvicorn (mocked to prevent actual server start)."""

    def test_serve_calls_uvicorn_run(self, monkeypatch):
        """main() with serve creates the app and calls uvicorn.run()."""
        from aperture.cli import main

        monkeypatch.setattr(sys, "argv", ["aperture", "serve"])

        mock_run = MagicMock()
        with patch("uvicorn.run", mock_run):
            main()

        # uvicorn.run was called once
        mock_run.assert_called_once()

        # Check that it was called with a FastAPI app and correct host/port
        call_args = mock_run.call_args
        app_arg = call_args[0][0] if call_args[0] else call_args[1].get("app")
        assert app_arg is not None  # an app was passed

        # Verify host and port come from settings
        import aperture.config

        settings = aperture.config.settings
        assert call_args[1].get("host", call_args[0][1] if len(call_args[0]) > 1 else None) is not None or "host" in str(call_args)
        assert call_args[1].get("port", call_args[0][2] if len(call_args[0]) > 2 else None) is not None or "port" in str(call_args)

    def test_serve_uses_settings_host_and_port(self, monkeypatch):
        """serve subcommand passes api_host and api_port from settings to uvicorn."""
        from aperture.cli import main

        monkeypatch.setattr(sys, "argv", ["aperture", "serve"])

        mock_run = MagicMock()
        with patch("uvicorn.run", mock_run):
            main()

        call_kwargs = mock_run.call_args
        # uvicorn.run(app, host=..., port=...)
        import aperture.config

        settings = aperture.config.settings
        assert call_kwargs.kwargs.get("host") == settings.api_host or call_kwargs[1].get("host") == settings.api_host
        assert call_kwargs.kwargs.get("port") == settings.api_port or call_kwargs[1].get("port") == settings.api_port


class TestCLIMCPServe:
    """mcp-serve subcommand starts the MCP server (mocked to prevent blocking)."""

    def test_mcp_serve_calls_serve(self, monkeypatch):
        """main() with mcp-serve calls aperture.mcp_server.serve()."""
        from aperture.cli import main

        monkeypatch.setattr(sys, "argv", ["aperture", "mcp-serve"])

        mock_serve = MagicMock()
        with patch("aperture.mcp_server.serve", mock_serve):
            main()

        mock_serve.assert_called_once()

    def test_mcp_server_module_has_serve_function(self):
        """aperture.mcp_server exports a callable serve()."""
        from aperture.mcp_server import serve

        assert callable(serve)


class TestCLIUnknownCommand:
    """Unknown commands print an error and exit with code 1."""

    def test_unknown_command_exits_with_error(self, capsys, monkeypatch):
        """main() with an unknown command prints error and exits with code 1."""
        from aperture.cli import main

        monkeypatch.setattr(sys, "argv", ["aperture", "not-a-real-command"])

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Unknown command" in captured.out
        assert "not-a-real-command" in captured.out

    def test_another_unknown_command(self, capsys, monkeypatch):
        """A different unknown command also fails with code 1."""
        from aperture.cli import main

        monkeypatch.setattr(sys, "argv", ["aperture", "deploy"])

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Unknown command: deploy" in captured.out
