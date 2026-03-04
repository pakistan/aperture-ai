"""Map Claude Code tools to AIperture (tool, action, scope) triples.

Claude Code exposes tools like Bash, Edit, Write, Read, Glob, Grep,
WebFetch, WebSearch, and MCP tools (mcp__server__tool). This module
translates each into the (tool, action, scope) triple AIperture uses
for permission tracking and learning.
"""

from __future__ import annotations

from typing import Any


def map_tool(tool_name: str, tool_input: dict[str, Any]) -> tuple[str, str, str] | None:
    """Map a Claude Code tool call to (tool, action, scope).

    Returns None if the tool should be skipped (e.g. mcp__aiperture__* to
    prevent recursive loops).

    Args:
        tool_name: The Claude Code tool name (e.g. "Bash", "Edit").
        tool_input: The tool's input parameters dict.

    Returns:
        (tool, action, scope) triple, or None to skip.
    """
    # Skip AIperture's own MCP tools to prevent recursive loops
    if tool_name.startswith("mcp__aiperture__"):
        return None

    name_lower = tool_name.lower()

    # Shell tools
    if name_lower in ("bash", "shell", "terminal"):
        command = tool_input.get("command", "")
        return ("shell", "execute", command)

    # Filesystem write tools
    if name_lower == "edit":
        file_path = tool_input.get("file_path", "")
        return ("filesystem", "write", file_path)

    if name_lower == "write":
        file_path = tool_input.get("file_path", "")
        return ("filesystem", "write", file_path)

    if name_lower == "notebookedit":
        notebook_path = tool_input.get("notebook_path", "")
        return ("filesystem", "write", notebook_path)

    # Filesystem read tools
    if name_lower == "read":
        file_path = tool_input.get("file_path", "")
        return ("filesystem", "read", file_path)

    if name_lower == "glob":
        pattern = tool_input.get("pattern", "")
        return ("filesystem", "read", pattern)

    if name_lower == "grep":
        pattern = tool_input.get("pattern", "")
        path = tool_input.get("path", "")
        scope = f"{path}:{pattern}" if path else pattern
        return ("filesystem", "read", scope)

    # Web tools
    if name_lower == "webfetch":
        url = tool_input.get("url", "")
        return ("web", "fetch", url)

    if name_lower == "websearch":
        query = tool_input.get("query", "")
        return ("web", "search", query)

    # Agent tool — map based on subagent type
    if name_lower == "agent":
        subagent = tool_input.get("subagent_type", "agent")
        description = tool_input.get("description", "")
        return ("agent", "spawn", f"{subagent}:{description}")

    # MCP tools from other servers: mcp__<server>__<tool>
    if tool_name.startswith("mcp__"):
        parts = tool_name.split("__", 2)
        if len(parts) == 3:
            server = parts[1]
            mcp_tool = parts[2]
            # Use first string value from params as scope, or tool name
            scope = _extract_mcp_scope(tool_input) or mcp_tool
            return (server, mcp_tool, scope)

    # Unknown tool — use generic mapping
    return ("unknown", tool_name, str(tool_input.get("scope", tool_input.get("path", ""))))


def _extract_mcp_scope(params: dict[str, Any]) -> str:
    """Extract a reasonable scope string from MCP tool parameters.

    Looks for common parameter names that represent a resource scope.
    """
    for key in ("scope", "path", "file_path", "url", "query", "command", "resource"):
        val = params.get(key)
        if val and isinstance(val, str):
            return val
    return ""
