"""Aperture configuration via environment variables.

All config uses APERTURE_ prefix. Example: APERTURE_DB_PATH=./data.sqlite

Tunable settings can also be read from .aperture.env and updated at runtime
via the config API, CLI wizard, or MCP tools.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="APERTURE_",
        env_file=".aperture.env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database
    db_backend: str = "sqlite"  # "sqlite" | "postgres"
    db_path: str = "aperture.db"
    postgres_url: str = ""

    # Permissions
    permission_learning_enabled: bool = True
    permission_learning_min_decisions: int = 10
    auto_approve_threshold: float = 0.95  # >95% approval rate -> auto-approve
    auto_deny_threshold: float = 0.05  # <5% approval rate -> auto-deny

    # Intelligence (cross-org)
    intelligence_enabled: bool = False  # opt-in
    intelligence_epsilon: float = 1.0  # local DP noise level (higher = less private)
    intelligence_min_orgs: int = 5  # minimum orgs before surfacing global signal

    # Artifacts
    artifact_storage_dir: str = ""

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8100

    # --- Tunable field metadata (not persisted) ---

    TUNABLE_FIELDS: ClassVar[frozenset[str]] = frozenset({
        "permission_learning_enabled",
        "permission_learning_min_decisions",
        "auto_approve_threshold",
        "auto_deny_threshold",
        "intelligence_enabled",
        "intelligence_epsilon",
        "intelligence_min_orgs",
    })

    TUNABLE_DESCRIPTIONS: ClassVar[dict[str, str]] = {
        "permission_learning_enabled": "Auto-learn from human approval/denial decisions",
        "permission_learning_min_decisions": "Minimum human decisions before auto-deciding",
        "auto_approve_threshold": "Approval rate (0.0-1.0) to trigger auto-approve",
        "auto_deny_threshold": "Approval rate (0.0-1.0) to trigger auto-deny",
        "intelligence_enabled": "Enable cross-org differential-privacy intelligence",
        "intelligence_epsilon": "DP noise level (higher = more utility, less privacy)",
        "intelligence_min_orgs": "Minimum orgs required before surfacing global signal",
    }


def get_tunable_config() -> dict[str, Any]:
    """Return current values of all tunable settings."""
    return {field: getattr(settings, field) for field in Settings.TUNABLE_FIELDS}


def update_settings(
    updates: dict[str, Any],
    env_file_path: str | None = None,
) -> Settings:
    """Update tunable settings in-memory and persist to .aperture.env.

    Args:
        updates: Dict of field_name -> new_value. Only TUNABLE_FIELDS accepted.
        env_file_path: Path to write .aperture.env. Defaults to ".aperture.env".

    Returns:
        The updated Settings singleton.

    Raises:
        ValueError: If a non-tunable field is provided or validation fails.
    """
    global settings

    bad_fields = set(updates) - Settings.TUNABLE_FIELDS
    if bad_fields:
        raise ValueError(
            f"Non-tunable fields cannot be updated at runtime: {sorted(bad_fields)}"
        )

    # Cross-field validation
    approve = updates.get("auto_approve_threshold", settings.auto_approve_threshold)
    deny = updates.get("auto_deny_threshold", settings.auto_deny_threshold)
    if approve <= deny:
        raise ValueError(
            f"auto_approve_threshold ({approve}) must be greater than "
            f"auto_deny_threshold ({deny})"
        )

    # Apply in-memory
    for field, value in updates.items():
        object.__setattr__(settings, field, value)

    # Persist to .aperture.env
    _write_env_file(env_file_path or ".aperture.env")

    return settings


def _write_env_file(path: str) -> None:
    """Write all tunable settings to an env file."""
    lines = []
    for field in sorted(Settings.TUNABLE_FIELDS):
        value = getattr(settings, field)
        env_key = f"APERTURE_{field.upper()}"
        lines.append(f"{env_key}={value}")
    Path(path).write_text("\n".join(lines) + "\n")


# Module-level singleton — access via `aperture.config.settings`
settings = Settings()
