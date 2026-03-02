"""Cross-org anonymized intelligence — differential privacy protected.

Uses RAPPOR-inspired local differential privacy:
- Noise added client-side before data leaves the org
- Central server debiases to estimate true distribution
- No org_id stored in global tables

Privacy model:
- randomized_response: with probability p report truth, else random
- debias: recover estimated true rate from noisy observations
- Scope generalization: strips identifying details before storage
"""

import logging
import math
import random
import re
from datetime import datetime, timezone

from sqlmodel import Session, select

from aperture.db import get_engine
from aperture.models.intelligence import GlobalPermissionStat
from aperture.models.verdict import GlobalSignal

logger = logging.getLogger(__name__)


class IntelligenceEngine:
    """Cross-organization permission intelligence with differential privacy."""

    def __init__(self, min_orgs: int = 5, default_epsilon: float = 1.0):
        self.min_orgs = min_orgs
        self.default_epsilon = default_epsilon

    def report_decision(
        self,
        tool: str,
        action: str,
        scope: str,
        decision_is_allow: bool,
        epsilon: float | None = None,
    ) -> None:
        """Report a decision with local differential privacy.

        Noise is added to the decision before storage — the true decision
        is never stored in the global table.
        """
        eps = epsilon or self.default_epsilon
        scope_pattern = generalize_scope(scope)

        # Apply local DP: randomized response
        noisy_allow = randomized_response(decision_is_allow, eps)

        with Session(get_engine()) as session:
            # Find or create the global stat row
            stat = session.exec(
                select(GlobalPermissionStat).where(
                    GlobalPermissionStat.tool == tool,
                    GlobalPermissionStat.action == action,
                    GlobalPermissionStat.scope_pattern == scope_pattern,
                )
            ).first()

            if stat is None:
                stat = GlobalPermissionStat(
                    tool=tool,
                    action=action,
                    scope_pattern=scope_pattern,
                    total_orgs=1,
                    noisy_allow_count=1.0 if noisy_allow else 0.0,
                    noisy_deny_count=0.0 if noisy_allow else 1.0,
                    noisy_total=1.0,
                )
            else:
                stat.noisy_total += 1.0
                if noisy_allow:
                    stat.noisy_allow_count += 1.0
                else:
                    stat.noisy_deny_count += 1.0
                # Approximate org count (can't track without storing org_id)
                # Increment slowly to reflect new contributing orgs
                stat.total_orgs = max(stat.total_orgs, int(stat.noisy_total ** 0.5))

            # Debias to estimate true rate
            noisy_rate = stat.noisy_allow_count / stat.noisy_total if stat.noisy_total > 0 else 0.5
            stat.estimated_allow_rate = debias(noisy_rate, eps)
            stat.estimated_allow_rate = max(0.0, min(1.0, stat.estimated_allow_rate))

            # Confidence interval (wider with fewer samples and more noise)
            ci_half = confidence_interval_half_width(stat.noisy_total, eps)
            stat.confidence_low = max(0.0, stat.estimated_allow_rate - ci_half)
            stat.confidence_high = min(1.0, stat.estimated_allow_rate + ci_half)

            stat.last_updated = datetime.now(timezone.utc).replace(tzinfo=None)

            session.add(stat)
            session.commit()

    def get_global_signal(
        self,
        tool: str,
        action: str,
        scope: str,
    ) -> GlobalSignal | None:
        """Get cross-org signal for a permission pattern.

        Returns None if insufficient data (fewer than min_orgs).
        """
        scope_pattern = generalize_scope(scope)

        with Session(get_engine()) as session:
            stat = session.exec(
                select(GlobalPermissionStat).where(
                    GlobalPermissionStat.tool == tool,
                    GlobalPermissionStat.action == action,
                    GlobalPermissionStat.scope_pattern == scope_pattern,
                )
            ).first()

        if stat is None:
            return None

        if stat.total_orgs < self.min_orgs:
            return None

        return GlobalSignal(
            total_orgs=stat.total_orgs,
            estimated_allow_rate=stat.estimated_allow_rate,
            confidence_interval=(stat.confidence_low, stat.confidence_high),
            sample_size=int(stat.noisy_total),
        )


# ── Differential privacy primitives ──────────────────────────────────


def randomized_response(true_value: bool, epsilon: float) -> bool:
    """Local DP: with probability p report truth, else report random.

    p = e^epsilon / (1 + e^epsilon)

    Higher epsilon = more truthful (less private).
    epsilon=0 → coin flip (maximum privacy, no utility).
    epsilon=inf → always truth (no privacy).
    """
    p = math.exp(epsilon) / (1.0 + math.exp(epsilon))
    if random.random() < p:
        return true_value
    return random.random() < 0.5


def debias(noisy_rate: float, epsilon: float) -> float:
    """Recover estimated true rate from noisy observations.

    Inverts the randomized response to estimate the true proportion.
    """
    p = math.exp(epsilon) / (1.0 + math.exp(epsilon))
    denominator = 2.0 * p - 1.0
    if abs(denominator) < 1e-10:
        return 0.5  # epsilon ≈ 0, no information
    return (noisy_rate - 0.5 * (1.0 - p)) / denominator


def confidence_interval_half_width(n: float, epsilon: float) -> float:
    """Approximate 95% confidence interval half-width for DP estimate.

    Combines sampling uncertainty with DP noise.
    """
    if n <= 0:
        return 0.5

    p = math.exp(epsilon) / (1.0 + math.exp(epsilon))
    denominator = 2.0 * p - 1.0
    if abs(denominator) < 1e-10:
        return 0.5

    # Sampling variance + DP variance
    sampling_var = 0.25 / n  # worst-case binomial variance
    dp_var = (1.0 / (denominator ** 2)) * (0.25 / n)
    total_var = sampling_var + dp_var

    return 1.96 * math.sqrt(total_var)


# ── Scope generalization ─────────────────────────────────────────────


def generalize_scope(scope: str) -> str:
    """Generalize scope for privacy — strip identifying details.

    Preserves command structure but replaces specific paths, names,
    and identifiers with patterns.
    """
    s = scope.strip()
    if not s:
        return "*"

    # Replace specific file paths: /Users/john/project/src/main.py → *.py
    s = re.sub(r"(/[\w./-]+/)?(\w+\.\w{1,5})\b", r"*.\2", s)
    # Clean up double-wildcards from substitution
    s = re.sub(r"\*\.\*\.(\w+)", r"*.\1", s)

    # Replace specific directory paths with wildcard
    s = re.sub(r"\./[\w./-]+/", ".//", s)

    # Replace table/database names in SQL
    s = re.sub(r"(TABLE|DATABASE|FROM|INTO|UPDATE)\s+[`\"']?\w+[`\"']?", r"\1 *", s, flags=re.IGNORECASE)

    # Replace URLs
    s = re.sub(r"https?://[\w.-]+(?:/[\w./-]*)?", "https://*", s)

    # Replace UUIDs
    s = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "*", s, flags=re.IGNORECASE)

    # Replace numeric IDs
    s = re.sub(r"\b\d{3,}\b", "*", s)

    return s
