"""Permission engine — deterministic RBAC + ReBAC + learning + intelligence."""

from aperture.permissions.crowd import compute_auto_approve_distance, compute_trend, get_org_signal
from aperture.permissions.engine import PermissionEngine
from aperture.permissions.explainer import explain_action
from aperture.permissions.intelligence import IntelligenceEngine
from aperture.permissions.learning import PermissionLearner, PermissionPattern
from aperture.permissions.resource import extract_resource
from aperture.permissions.risk import classify_risk
from aperture.permissions.similarity import find_similar_patterns

__all__ = [
    "IntelligenceEngine",
    "PermissionEngine",
    "PermissionLearner",
    "PermissionPattern",
    "classify_risk",
    "compute_auto_approve_distance",
    "compute_trend",
    "explain_action",
    "extract_resource",
    "find_similar_patterns",
    "get_org_signal",
]
