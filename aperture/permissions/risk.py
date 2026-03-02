"""Risk classification — deterministic scoring of (tool, action, scope) triples.

Uses OWASP-inspired likelihood × impact model with CRITICAL overrides.
Zero ML. Zero LLM calls. Pure pattern matching and arithmetic.
"""

import fnmatch
import re

from aperture.models.verdict import RiskAssessment, RiskTier

# ── Danger maps ──────────────────────────────────────────────────────

# Tool danger: how capable is this tool of causing harm (likelihood dimension)
TOOL_DANGER: dict[str, float] = {
    "shell": 0.9,
    "bash": 0.9,
    "terminal": 0.9,
    "database": 0.8,
    "db": 0.8,
    "sql": 0.8,
    "network": 0.7,
    "http": 0.6,
    "filesystem": 0.6,
    "file": 0.6,
    "fs": 0.6,
    "api": 0.5,
    "browser": 0.4,
    "read": 0.1,
    "viewer": 0.1,
}

# Action severity: how much damage can this action do (impact dimension)
ACTION_SEVERITY: dict[str, float] = {
    "drop": 0.95,
    "truncate": 0.9,
    "execute": 0.9,
    "delete": 0.8,
    "remove": 0.8,
    "destroy": 0.9,
    "format": 0.95,
    "overwrite": 0.7,
    "write": 0.5,
    "modify": 0.5,
    "update": 0.4,
    "create": 0.3,
    "insert": 0.3,
    "post": 0.4,
    "put": 0.4,
    "patch": 0.3,
    "read": 0.1,
    "get": 0.1,
    "list": 0.1,
    "query": 0.2,
    "select": 0.1,
    "view": 0.1,
}

# Actions that are reversible
REVERSIBLE_ACTIONS = frozenset({
    "read", "get", "list", "view", "query", "select",
    "create", "insert", "post",  # can be undone by delete
})

# ── CRITICAL override patterns ───────────────────────────────────────
# If scope matches any of these, result is ALWAYS CRITICAL.

CRITICAL_PATTERNS = [
    "rm -rf /",
    "rm -rf /*",
    "rm -rf ~",
    "rm -rf ~/*",
    "rm -rf .",
    "rm -rf ./*",
    "DROP DATABASE*",
    "DROP TABLE*",
    "TRUNCATE TABLE*",
    "format *",
    "mkfs*",
    "> /dev/*",
    "dd if=/dev/zero*",
    "dd if=/dev/random*",
    "chmod -R 777 /",
    "chmod -R 777 /*",
    ":(){ :|:& };:",
    "sudo rm -rf /",
    "sudo rm -rf /*",
]

# ── Scope analysis ───────────────────────────────────────────────────

# Patterns that indicate broad scope
_BROAD_PATTERNS = re.compile(r"(\*\*|/\*$|/\*\s|\s\*$|\s-[rR]\s|\s-rf\s|--recursive)")

# Patterns that indicate destructive intent
_DESTRUCTIVE_MARKERS = frozenset({
    "rm ", "rm\t", "rmdir", "delete", "drop ", "truncate", "format ",
    "--force", "-rf", "-f ", "overwrite", "destroy", "> /dev/",
    "dd if=", "mkfs", "shred",
})

# Root/system paths
_SYSTEM_PATHS = re.compile(r"^(/etc|/usr|/bin|/sbin|/var|/boot|/sys|/proc|/dev|C:\\Windows)")

# Production indicators
_PRODUCTION_MARKERS = re.compile(r"(production|prod\b|\.prod\.|live|master\.)", re.IGNORECASE)


def scope_breadth(scope: str) -> float:
    """Score how broad the scope is: 0.0 (very specific) to 1.0 (dangerously broad).

    Wildcards, root paths, and recursive flags increase breadth.
    Specific filenames and relative paths decrease breadth.
    """
    if not scope:
        return 0.5

    score = 0.0

    # Wildcards
    wildcard_count = scope.count("*") + scope.count("?")
    if wildcard_count > 0:
        score += min(wildcard_count * 0.2, 0.4)

    # Recursive/broad patterns
    if _BROAD_PATTERNS.search(scope):
        score += 0.3

    # Root/system paths
    if _SYSTEM_PATHS.search(scope):
        score += 0.2

    # Production environment
    if _PRODUCTION_MARKERS.search(scope):
        score += 0.15

    # Very short scope with wildcards = dangerously broad
    if len(scope) < 5 and "*" in scope:
        score += 0.2

    # Specific file paths reduce breadth
    if "/" in scope and "*" not in scope and "?" not in scope:
        depth = scope.count("/")
        score -= min(depth * 0.05, 0.2)

    # File extension = specific
    if re.search(r"\.\w{1,5}$", scope) and "*" not in scope:
        score -= 0.1

    return max(0.0, min(1.0, score))


def _matches_critical_pattern(scope: str) -> bool:
    """Check if scope matches any CRITICAL override pattern."""
    scope_stripped = scope.strip()
    for pattern in CRITICAL_PATTERNS:
        if fnmatch.fnmatch(scope_stripped, pattern):
            return True
        # Also check if the scope contains the pattern
        if pattern.rstrip("*") and pattern.rstrip("*") in scope_stripped:
            if pattern.endswith("*"):
                return True
    return False


def _collect_risk_factors(tool: str, action: str, scope: str) -> list[str]:
    """Collect human-readable risk factors."""
    factors = []

    scope_lower = scope.lower()
    for marker in _DESTRUCTIVE_MARKERS:
        if marker in scope_lower or marker in scope:
            factors.append("destructive_action")
            break

    if _BROAD_PATTERNS.search(scope):
        factors.append("broad_scope")

    if _SYSTEM_PATHS.search(scope):
        factors.append("system_path")

    if _PRODUCTION_MARKERS.search(scope):
        factors.append("production_target")

    if TOOL_DANGER.get(tool.lower(), 0.5) >= 0.8:
        factors.append("high_danger_tool")

    if ACTION_SEVERITY.get(action.lower(), 0.5) >= 0.8:
        factors.append("high_severity_action")

    return factors


def classify_risk(tool: str, action: str, scope: str) -> RiskAssessment:
    """Classify the risk of a (tool, action, scope) triple.

    Uses OWASP-inspired likelihood × impact model:
    - likelihood = tool danger
    - impact = action severity × scope breadth amplifier
    - CRITICAL override for known catastrophic patterns

    Returns:
        RiskAssessment with tier, score, factors, and reversibility.
    """
    factors = _collect_risk_factors(tool, action, scope)

    # 1. CRITICAL override — matches catastrophic patterns
    if _matches_critical_pattern(scope):
        return RiskAssessment(
            tier=RiskTier.CRITICAL,
            score=1.0,
            factors=["critical_pattern_match"] + factors,
            reversible=False,
        )

    # 2. OWASP-style: likelihood × impact
    tool_lower = tool.lower()
    action_lower = action.lower()

    likelihood = TOOL_DANGER.get(tool_lower, 0.5)
    severity = ACTION_SEVERITY.get(action_lower, 0.5)
    breadth = scope_breadth(scope)

    # Breadth amplifies severity: narrow scope reduces impact, broad scope increases it
    impact = severity * (0.6 + 0.4 * breadth)
    score = likelihood * impact

    # 3. Map to tier
    if score >= 0.6:
        tier = RiskTier.HIGH
    elif score >= 0.3:
        tier = RiskTier.MEDIUM
    else:
        tier = RiskTier.LOW

    # 4. Reversibility
    reversible = action_lower in REVERSIBLE_ACTIONS

    return RiskAssessment(
        tier=tier,
        score=score,
        factors=factors,
        reversible=reversible,
    )
