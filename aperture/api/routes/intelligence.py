"""Intelligence API — cross-org anonymized permission signals."""

from fastapi import APIRouter

from aperture.permissions.intelligence import IntelligenceEngine

router = APIRouter()


@router.get("/global-signal")
def get_global_signal(
    tool: str,
    action: str,
    scope: str,
):
    """Get cross-organization permission signal for a pattern.

    Returns DP-protected aggregate statistics. Only available when
    enough organizations have contributed data (min_orgs threshold).
    """
    import aperture.config

    intel = IntelligenceEngine(
        min_orgs=aperture.config.settings.intelligence_min_orgs,
        default_epsilon=aperture.config.settings.intelligence_epsilon,
    )
    signal = intel.get_global_signal(tool, action, scope)

    if signal is None:
        return {"available": False, "reason": "Insufficient cross-org data"}

    return {
        "available": True,
        "total_orgs": signal.total_orgs,
        "estimated_allow_rate": round(signal.estimated_allow_rate, 3),
        "confidence_interval": [
            round(signal.confidence_interval[0], 3),
            round(signal.confidence_interval[1], 3),
        ],
        "sample_size": signal.sample_size,
    }
