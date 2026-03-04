"""AIperture configuration via environment variables.

All config uses AIPERTURE_ prefix. Example: AIPERTURE_DB_PATH=./data.sqlite

Tunable settings can also be read from .aiperture.env and updated at runtime
via the config API, CLI wizard, or MCP tools.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, ClassVar

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AIPERTURE_",
        env_file=".aiperture.env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database
    db_backend: str = "sqlite"  # "sqlite" | "postgres"
    db_path: str = "aiperture.db"
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

    # Security hardening
    sensitive_patterns: str = "*secret*,*credential*,*password*,*.env,*.pem,*.key,*token*,.env*,*id_rsa*,*private*"
    pattern_max_age_days: int = 90  # auto-learned patterns expire after N days without human reconfirmation
    rapid_approval_window_seconds: int = 60  # window for detecting rubber-stamping
    rapid_approval_min_count: int = 5  # min rapid approvals to flag as rubber-stamping
    rate_limit_per_minute: int = 200  # max permission checks per session per minute
    session_risk_budget: float = 50.0  # cumulative risk budget per session

    # Compliance
    compliance_tracking_enabled: bool = True  # track checked vs unchecked tool executions

    # Artifacts
    artifact_storage_dir: str = ""

    # Logging
    log_level: str = "DEBUG"  # DEBUG, INFO, WARNING, ERROR
    log_file: str = ""  # Path to log file (e.g. ~/.aiperture/aiperture.log)

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8100
    api_key: str = ""  # If set, requires Authorization: Bearer <key> on all HTTP requests

    # --- Tunable field metadata (not persisted) ---

    TUNABLE_FIELDS: ClassVar[frozenset[str]] = frozenset({
        "permission_learning_enabled",
        "permission_learning_min_decisions",
        "auto_approve_threshold",
        "auto_deny_threshold",
        "intelligence_enabled",
        "intelligence_epsilon",
        "intelligence_min_orgs",
        "sensitive_patterns",
        "pattern_max_age_days",
        "rapid_approval_window_seconds",
        "rapid_approval_min_count",
        "rate_limit_per_minute",
        "session_risk_budget",
        "log_level",
    })

    TUNABLE_DESCRIPTIONS: ClassVar[dict[str, str]] = {
        "permission_learning_enabled": "Auto-learn from human approval/denial decisions",
        "permission_learning_min_decisions": "Minimum human decisions before auto-deciding",
        "auto_approve_threshold": "Approval rate (0.0-1.0) to trigger auto-approve",
        "auto_deny_threshold": "Approval rate (0.0-1.0) to trigger auto-deny",
        "intelligence_enabled": "Enable cross-org differential-privacy intelligence",
        "intelligence_epsilon": "DP noise level (higher = more utility, less privacy)",
        "intelligence_min_orgs": "Minimum orgs required before surfacing global signal",
        "sensitive_patterns": "Comma-separated glob patterns for sensitive files (skip scope normalization)",
        "pattern_max_age_days": "Days before auto-learned patterns expire without human reconfirmation",
        "rapid_approval_window_seconds": "Time window (seconds) for rubber-stamping detection",
        "rapid_approval_min_count": "Min approvals within window to flag as rubber-stamping",
        "rate_limit_per_minute": "Max permission checks per session per minute (0 = unlimited)",
        "session_risk_budget": "Cumulative risk budget per session before escalating to ASK",
        "log_level": "Logging verbosity: DEBUG (all decisions), INFO (deny+ask), WARNING (deny only), ERROR",
    }


    @property
    def sensitive_patterns_list(self) -> list[str]:
        """Return sensitive_patterns as a list of glob patterns."""
        return [p.strip() for p in self.sensitive_patterns.split(",") if p.strip()]


def get_tunable_config() -> dict[str, Any]:
    """Return current values of all tunable settings."""
    return {field: getattr(settings, field) for field in Settings.TUNABLE_FIELDS}


def update_settings(
    updates: dict[str, Any],
    env_file_path: str | None = None,
) -> Settings:
    """Update tunable settings in-memory and persist to .aiperture.env.

    Args:
        updates: Dict of field_name -> new_value. Only TUNABLE_FIELDS accepted.
        env_file_path: Path to write .aiperture.env. Defaults to ".aiperture.env".

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

    # Type coercion — validate types match the field annotations
    field_types = {
        "permission_learning_enabled": bool,
        "permission_learning_min_decisions": int,
        "auto_approve_threshold": float,
        "auto_deny_threshold": float,
        "intelligence_enabled": bool,
        "intelligence_epsilon": float,
        "intelligence_min_orgs": int,
        "sensitive_patterns": str,
        "pattern_max_age_days": int,
        "rapid_approval_window_seconds": int,
        "rapid_approval_min_count": int,
        "rate_limit_per_minute": int,
        "session_risk_budget": float,
        "log_level": str,
    }
    coerced: dict[str, Any] = {}
    for field, value in updates.items():
        expected_type = field_types.get(field)
        if expected_type is not None:
            try:
                coerced[field] = expected_type(value)
            except (TypeError, ValueError):
                raise ValueError(
                    f"Invalid type for {field}: expected {expected_type.__name__}, got {type(value).__name__}"
                )
        else:
            coerced[field] = value

    # Range validation
    approve = coerced.get("auto_approve_threshold", settings.auto_approve_threshold)
    deny = coerced.get("auto_deny_threshold", settings.auto_deny_threshold)
    if not (0.0 <= deny < approve <= 1.0):
        raise ValueError(
            f"Thresholds must satisfy 0.0 <= auto_deny_threshold ({deny}) "
            f"< auto_approve_threshold ({approve}) <= 1.0"
        )

    min_decisions = coerced.get("permission_learning_min_decisions", settings.permission_learning_min_decisions)
    if min_decisions < 1:
        raise ValueError(f"permission_learning_min_decisions must be >= 1, got {min_decisions}")

    epsilon = coerced.get("intelligence_epsilon", settings.intelligence_epsilon)
    if epsilon <= 0:
        raise ValueError(f"intelligence_epsilon must be > 0, got {epsilon}")

    min_orgs = coerced.get("intelligence_min_orgs", settings.intelligence_min_orgs)
    if min_orgs < 1:
        raise ValueError(f"intelligence_min_orgs must be >= 1, got {min_orgs}")

    log_level = coerced.get("log_level", settings.log_level).upper()
    if log_level not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        raise ValueError(f"log_level must be DEBUG, INFO, WARNING, or ERROR, got {log_level}")
    if "log_level" in coerced:
        coerced["log_level"] = log_level

    # Apply in-memory (using coerced/validated values)
    for field, value in coerced.items():
        object.__setattr__(settings, field, value)

    # Persist to .aiperture.env
    _write_env_file(env_file_path or ".aiperture.env")

    return settings


def _write_env_file(path: str) -> None:
    """Write all tunable settings to an env file."""
    lines = []
    for field in sorted(Settings.TUNABLE_FIELDS):
        value = getattr(settings, field)
        env_key = f"AIPERTURE_{field.upper()}"
        lines.append(f"{env_key}={value}")
    Path(path).write_text("\n".join(lines) + "\n")


# Plugin config sections — plugins can register additional config via register_plugin_config()
_plugin_configs: dict[str, dict] = {}


def register_plugin_config(name: str, fields: dict) -> None:
    """Register additional config fields from a plugin.

    Args:
        name: Plugin name (e.g. "enterprise").
        fields: Dict of field_name -> {"default": ..., "description": ...}.
    """
    _plugin_configs[name] = fields


def get_plugin_configs() -> dict[str, dict]:
    """Return all registered plugin config sections."""
    return dict(_plugin_configs)


# Module-level singleton — access via `aiperture.config.settings`
settings = Settings()


def setup_file_logging() -> None:
    """Add a RotatingFileHandler to the root logger when log_file is set.

    Creates parent directories automatically. Expands ~ in paths.
    No-op when log_file is empty.
    """
    if not settings.log_file:
        return

    log_path = Path(settings.log_file).expanduser()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    handler = RotatingFileHandler(
        str(log_path),
        maxBytes=5 * 1024 * 1024,  # 5 MB
        backupCount=3,
    )
    handler.setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))
    handler.setFormatter(
        logging.Formatter("%(asctime)s [aiperture] %(levelname)s %(message)s")
    )
    logging.getLogger().addHandler(handler)
