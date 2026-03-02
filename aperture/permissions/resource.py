"""Resource extractor — normalizes scope to target resource regardless of mechanism.

shell.execute "rm -rf ./build/" → "./build/"
filesystem.delete "./build/"    → "./build/"

This enables similarity matching by intent (what's affected) not mechanism (which tool).
"""

import re
import shlex


# Shell commands where the last positional arg is the target
_TARGET_LAST_CMDS = frozenset({
    "rm", "cat", "head", "tail", "less", "more", "chmod", "chown",
    "touch", "mkdir", "rmdir", "stat", "file", "wc", "du",
})

# Shell commands where the last arg is destination, second-to-last is source
_COPY_CMDS = frozenset({"cp", "mv", "ln", "scp", "rsync"})

# SQL statement patterns
_SQL_TABLE_RE = re.compile(
    r"(?:FROM|INTO|UPDATE|TABLE|JOIN|DROP\s+TABLE|TRUNCATE\s+TABLE|ALTER\s+TABLE)\s+"
    r"[`\"']?(\w+)[`\"']?",
    re.IGNORECASE,
)


def extract_resource(tool: str, action: str, scope: str) -> str:
    """Normalize scope to the target resource.

    Args:
        tool: Tool name (shell, filesystem, api, database, etc.)
        action: Action name
        scope: Raw scope string

    Returns:
        Normalized resource string. Falls back to scope if unparseable.
    """
    if not scope:
        return ""

    tool_lower = tool.lower()

    if tool_lower in ("shell", "bash", "terminal"):
        return _parse_shell_target(scope)
    elif tool_lower in ("filesystem", "file", "fs"):
        return scope.strip()
    elif tool_lower in ("api", "http", "network"):
        return _strip_protocol(scope)
    elif tool_lower in ("database", "db", "sql"):
        return _parse_sql_target(scope)
    return scope.strip()


def _parse_shell_target(scope: str) -> str:
    """Extract the file/directory target from a shell command."""
    scope = scope.strip()
    if not scope:
        return ""

    try:
        parts = shlex.split(scope)
    except ValueError:
        parts = scope.split()

    if not parts:
        return scope

    cmd = parts[0].split("/")[-1]  # handle /usr/bin/rm → rm

    # Filter out flags (anything starting with -)
    positional = [p for p in parts[1:] if not p.startswith("-")]

    if not positional:
        return scope

    if cmd in _TARGET_LAST_CMDS:
        return positional[-1]

    if cmd in _COPY_CMDS:
        # Destination is last, source(s) are earlier
        return positional[-1] if positional else scope

    if cmd in ("cd", "pushd"):
        return positional[0]

    # For unknown commands, return the last positional arg as best guess
    return positional[-1] if positional else scope


def _strip_protocol(scope: str) -> str:
    """Strip protocol from URLs: https://api.example.com/users → api.example.com/users."""
    scope = scope.strip()
    if "://" in scope:
        return scope.split("://", 1)[1]
    return scope


def _parse_sql_target(scope: str) -> str:
    """Extract table name from SQL statements."""
    match = _SQL_TABLE_RE.search(scope)
    if match:
        return match.group(1)
    return scope.strip()
