"""Similarity matching — finds structurally similar permission patterns.

Uses domain-specific distance functions instead of generic edit distance:
- Tool/action taxonomy distance (MITRE ATT&CK inspired)
- Path-prefix distance for filesystem scopes
- Resource-based intent matching

When there's no exact decision history for a request, similar patterns
help the user make an informed decision.
"""

import fnmatch
import logging
import os.path

from sqlmodel import Session, select

from aperture.db import get_engine
from aperture.models.permission import PermissionDecision, PermissionLog
from aperture.models.verdict import SimilarPattern

logger = logging.getLogger(__name__)

# ── Tool/action taxonomy ─────────────────────────────────────────────

TOOL_TAXONOMY: dict[str, str] = {
    "shell": "execution",
    "bash": "execution",
    "terminal": "execution",
    "database": "data_access",
    "db": "data_access",
    "sql": "data_access",
    "filesystem": "file_access",
    "file": "file_access",
    "fs": "file_access",
    "api": "network",
    "http": "network",
    "network": "network",
    "browser": "interaction",
    "read": "observation",
    "viewer": "observation",
}

ACTION_TAXONOMY: dict[str, str] = {
    "execute": "modify",
    "delete": "modify",
    "remove": "modify",
    "drop": "modify",
    "truncate": "modify",
    "destroy": "modify",
    "write": "modify",
    "create": "modify",
    "insert": "modify",
    "update": "modify",
    "modify": "modify",
    "overwrite": "modify",
    "post": "modify",
    "put": "modify",
    "read": "observe",
    "get": "observe",
    "list": "observe",
    "view": "observe",
    "query": "observe",
    "select": "observe",
}


def tool_action_similarity(tool1: str, action1: str, tool2: str, action2: str) -> float:
    """Compute taxonomy-based similarity between two (tool, action) pairs.

    Returns 0.0 (completely different) to 1.0 (identical).
    """
    t1, a1 = tool1.lower(), action1.lower()
    t2, a2 = tool2.lower(), action2.lower()

    # Tool similarity
    if t1 == t2:
        tool_sim = 1.0
    elif TOOL_TAXONOMY.get(t1) == TOOL_TAXONOMY.get(t2) and TOOL_TAXONOMY.get(t1) is not None:
        tool_sim = 0.7
    else:
        tool_sim = 0.2

    # Action similarity
    if a1 == a2:
        action_sim = 1.0
    elif ACTION_TAXONOMY.get(a1) == ACTION_TAXONOMY.get(a2) and ACTION_TAXONOMY.get(a1) is not None:
        action_sim = 0.7
    else:
        action_sim = 0.2

    return tool_sim * 0.5 + action_sim * 0.5


def scope_similarity(scope1: str, scope2: str) -> float:
    """Compute domain-specific scope similarity.

    Uses path-prefix matching for file paths, glob containment,
    and command similarity for shell scopes.

    Returns 0.0 (completely different) to 1.0 (identical).
    """
    if scope1 == scope2:
        return 1.0

    s1, s2 = scope1.strip(), scope2.strip()
    if not s1 or not s2:
        return 0.0

    # Glob containment: if one is a glob that matches the other
    try:
        if fnmatch.fnmatch(s1, s2) or fnmatch.fnmatch(s2, s1):
            return 0.8
    except Exception:
        pass

    # Path-based similarity (for filesystem paths and commands with paths)
    path_sim = _path_prefix_similarity(s1, s2)
    if path_sim > 0.3:
        return path_sim

    # Command similarity (for shell commands)
    cmd_sim = _command_similarity(s1, s2)
    if cmd_sim > 0.3:
        return cmd_sim

    # Fallback: normalized common prefix length
    common = os.path.commonprefix([s1, s2])
    if common:
        return len(common) / max(len(s1), len(s2))

    return 0.0


def resource_similarity(resource1: str, resource2: str) -> float:
    """Similarity based on normalized resource (intent matching).

    If both resources are non-empty, exact match = 1.0,
    path-prefix match = scaled. Empty resources = 0.0.
    """
    if not resource1 or not resource2:
        return 0.0

    if resource1 == resource2:
        return 1.0

    return _path_prefix_similarity(resource1, resource2)


def find_similar_patterns(
    tool: str,
    action: str,
    scope: str,
    organization_id: str = "default",
    min_similarity: float = 0.5,
    limit: int = 5,
) -> list[SimilarPattern]:
    """Find permission patterns similar to the given (tool, action, scope).

    Queries all distinct patterns from decision history, scores each,
    and returns the most similar ones with their allow/deny rates.
    """
    with Session(get_engine()) as session:
        logs = session.exec(
            select(PermissionLog).where(
                PermissionLog.organization_id == organization_id,
                PermissionLog.decided_by.startswith("human:"),  # type: ignore[union-attr]
            )
        ).all()

    if not logs:
        return []

    # Group by (tool, action, scope) to get distinct patterns
    groups: dict[tuple[str, str, str], list[PermissionLog]] = {}
    for log in logs:
        key = (log.tool, log.action, log.scope)
        groups.setdefault(key, []).append(log)

    candidates = []
    for (t, a, s), decisions in groups.items():
        # Skip exact match — caller already has that data
        if t == tool and a == action and s == scope:
            continue

        # Compute combined similarity
        ta_sim = tool_action_similarity(tool, action, t, a)
        s_sim = scope_similarity(scope, s)

        # Resource similarity if available
        r_sim = 0.0
        resources = [d.resource for d in decisions if d.resource]
        if resources:
            from aperture.permissions.resource import extract_resource
            my_resource = extract_resource(tool, action, scope)
            if my_resource:
                r_sim = max(resource_similarity(my_resource, r) for r in resources)

        # Weighted combination
        if r_sim > 0:
            combined = ta_sim * 0.30 + s_sim * 0.35 + r_sim * 0.35
        else:
            combined = ta_sim * 0.40 + s_sim * 0.60

        if combined < min_similarity:
            continue

        allow_count = sum(1 for d in decisions if d.decision == PermissionDecision.ALLOW)
        total = len(decisions)
        humans = {d.decided_by for d in decisions}

        candidates.append(SimilarPattern(
            tool=t,
            action=a,
            scope=s,
            similarity=combined,
            allow_rate=allow_count / total if total else 0.0,
            total_decisions=total,
            unique_humans=len(humans),
        ))

    # Sort by similarity descending, take top N
    candidates.sort(key=lambda p: p.similarity, reverse=True)
    return candidates[:limit]


# ── Internal helpers ─────────────────────────────────────────────────


def _path_prefix_similarity(path1: str, path2: str) -> float:
    """Compute similarity based on shared path prefix.

    /home/user/docs/ vs /home/user/docs/sub/ → high
    /home/user/docs/ vs /etc/passwd → low
    """
    parts1 = [p for p in path1.replace("\\", "/").split("/") if p]
    parts2 = [p for p in path2.replace("\\", "/").split("/") if p]

    if not parts1 or not parts2:
        return 0.0

    shared = 0
    for p1, p2 in zip(parts1, parts2):
        if p1 == p2:
            shared += 1
        else:
            break

    max_depth = max(len(parts1), len(parts2))
    return shared / max_depth if max_depth else 0.0


def _command_similarity(cmd1: str, cmd2: str) -> float:
    """Compute similarity between shell commands.

    "rm -rf ./build/" vs "rm -rf ./dist/" → same command, different target
    """
    parts1 = cmd1.split()
    parts2 = cmd2.split()

    if not parts1 or not parts2:
        return 0.0

    # Same command name
    if parts1[0] != parts2[0]:
        return 0.1

    # Same command — check flag similarity
    flags1 = {p for p in parts1[1:] if p.startswith("-")}
    flags2 = {p for p in parts2[1:] if p.startswith("-")}

    if flags1 == flags2:
        # Same command, same flags, different target
        return 0.7

    # Same command, different flags
    if flags1 and flags2:
        overlap = len(flags1 & flags2) / len(flags1 | flags2)
        return 0.4 + 0.3 * overlap

    return 0.4
