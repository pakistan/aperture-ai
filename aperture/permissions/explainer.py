"""Command explainer — template-based human-readable explanations.

Zero LLM calls. Generates explanations from tool/action/scope templates
and annotates with risk and destructive markers.
"""

from aperture.models.verdict import RiskAssessment, RiskTier

# ── Template registry ────────────────────────────────────────────────

TEMPLATES: dict[tuple[str, str], str] = {
    # Shell
    ("shell", "execute"): "Run shell command: {scope}",
    ("bash", "execute"): "Run bash command: {scope}",
    ("terminal", "execute"): "Run terminal command: {scope}",
    # Filesystem
    ("filesystem", "read"): "Read file: {scope}",
    ("filesystem", "write"): "Write to file: {scope}",
    ("filesystem", "delete"): "Delete: {scope}",
    ("filesystem", "create"): "Create file: {scope}",
    ("filesystem", "list"): "List directory: {scope}",
    ("filesystem", "modify"): "Modify file: {scope}",
    ("file", "read"): "Read file: {scope}",
    ("file", "write"): "Write to file: {scope}",
    ("file", "delete"): "Delete file: {scope}",
    # Database
    ("database", "query"): "Execute database query on: {scope}",
    ("database", "select"): "Query data from: {scope}",
    ("database", "insert"): "Insert data into: {scope}",
    ("database", "update"): "Update records in: {scope}",
    ("database", "delete"): "Delete records from: {scope}",
    ("database", "drop"): "Drop database object: {scope}",
    ("database", "truncate"): "Truncate table: {scope}",
    ("database", "create"): "Create database object: {scope}",
    ("db", "query"): "Execute database query on: {scope}",
    ("db", "drop"): "Drop database object: {scope}",
    # API / Network
    ("api", "call"): "Make API request to: {scope}",
    ("api", "get"): "GET request to: {scope}",
    ("api", "post"): "POST request to: {scope}",
    ("api", "put"): "PUT request to: {scope}",
    ("api", "delete"): "DELETE request to: {scope}",
    ("network", "connect"): "Open network connection to: {scope}",
    ("http", "get"): "HTTP GET: {scope}",
    ("http", "post"): "HTTP POST: {scope}",
    # Browser
    ("browser", "navigate"): "Navigate browser to: {scope}",
    ("browser", "click"): "Click element: {scope}",
}

# Markers detected in scope strings
_DESTRUCTIVE_MARKERS = frozenset({
    "rm ", "rm\t", "rmdir", "delete", "drop ", "drop\t",
    "truncate", "format ", "--force", "-rf", "overwrite",
    "destroy", "shred", "dd if=",
})

_BROAD_MARKERS = frozenset({
    " -R ", " -R\t", " -r ", " -r\t", "**", "/*", " * ", " *\t",
    "--recursive",
})


def explain_action(tool: str, action: str, scope: str, risk: RiskAssessment) -> str:
    """Generate a human-readable explanation of a permission request.

    Args:
        tool: Tool name
        action: Action name
        scope: Resource scope
        risk: Pre-computed risk assessment

    Returns:
        Human-readable explanation with risk annotations.
    """
    tool_lower = tool.lower()
    action_lower = action.lower()

    # Get base template
    template = TEMPLATES.get((tool_lower, action_lower))
    if template:
        base = template.format(scope=scope)
    else:
        base = f"Perform {action} using {tool} on: {scope}"

    # Collect annotations
    annotations = []

    if not risk.reversible:
        annotations.append("irreversible")

    if risk.tier in (RiskTier.HIGH, RiskTier.CRITICAL):
        annotations.append(f"{risk.tier.value} risk")

    scope_lower = scope.lower()
    is_destructive = any(marker in scope_lower or marker in scope for marker in _DESTRUCTIVE_MARKERS)
    if is_destructive:
        annotations.append("destructive")

    is_broad = any(marker in scope or marker in scope_lower for marker in _BROAD_MARKERS)
    if is_broad:
        annotations.append("broad scope")

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for a in annotations:
        if a not in seen:
            seen.add(a)
            unique.append(a)

    if unique:
        return f"{base} ({', '.join(unique)})"
    return base
