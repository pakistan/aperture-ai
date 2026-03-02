"""Global intelligence models — cross-org anonymized stats with differential privacy."""

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


class GlobalPermissionStat(SQLModel, table=True):
    """Aggregated permission stats across organizations. No org_id stored."""

    __tablename__ = "global_permission_stats"

    id: Optional[int] = Field(default=None, primary_key=True)
    tool: str = Field(index=True)
    action: str = Field(index=True)
    scope_pattern: str = Field(index=True)  # generalized scope (privacy-preserving)
    total_orgs: int = 0
    noisy_allow_count: float = 0.0  # DP-protected count
    noisy_deny_count: float = 0.0  # DP-protected count
    noisy_total: float = 0.0
    estimated_allow_rate: float = 0.0  # debiased from noisy counts
    confidence_low: float = 0.0
    confidence_high: float = 1.0
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
