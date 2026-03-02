# Setting Up Aperture with Claude Code

This guide walks you through adding Aperture as Claude Code's permission layer via MCP (Model Context Protocol). After setup, Claude Code will check permissions through Aperture before taking actions, and Aperture will learn your preferences over time.

## Prerequisites

- Python 3.12+
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) installed

## Step 1: Install Aperture

```bash
pip install aperture-ai
```

Verify it installed:

```bash
aperture --help
```

## Step 2: Initialize the database

```bash
aperture init-db
```

This creates `aperture.db` in the current directory (SQLite by default).

## Step 3: Add Aperture to your MCP config

Add the following to your `.mcp.json` (in your project root or `~/.claude/`):

```json
{
  "mcpServers": {
    "aperture": {
      "type": "stdio",
      "command": "aperture",
      "args": ["mcp-serve"]
    }
  }
}
```

If you already have other MCP servers configured, add the `"aperture"` key inside the existing `"mcpServers"` object.

## Step 4: Start using Claude Code

That's it. Claude Code now has access to 9 Aperture tools:

| Tool | What it does |
|------|-------------|
| `check_permission` | Check if an action is allowed (with risk assessment) |
| `approve_action` | Record a human approval |
| `deny_action` | Record a human denial |
| `explain_action` | Get a human-readable explanation of what an action does |
| `get_permission_patterns` | View what Aperture has learned from your decisions |
| `store_artifact` | Store an agent output with SHA-256 verification |
| `verify_artifact` | Verify an artifact's integrity |
| `get_cost_summary` | Get token and cost breakdown |
| `get_audit_trail` | Query the compliance audit trail |

## How the learning loop works

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  Claude Code                     Aperture                           │
│  ───────────                     ────────                           │
│                                                                     │
│  "I need to run npm test"                                           │
│         │                                                           │
│         ├──── check_permission ────▶  No history for this action.   │
│         │     tool: shell              Decision: DENY               │
│         │     action: execute                                       │
│         │     scope: npm test    ◀──── Return verdict ────┤         │
│         │                                                           │
│  "Permission denied. Approve?"                                      │
│         │                                                           │
│  User:  "Yes"                                                       │
│         │                                                           │
│         ├──── approve_action ─────▶  Recorded. (1 of 10 needed)     │
│         │                                                           │
│         │     ... 9 more approvals over time ...                    │
│         │                                                           │
│         ├──── check_permission ────▶  10/10 approvals at 100%.      │
│         │     tool: shell              Decision: ALLOW              │
│         │     action: execute          Decided by: auto_learned     │
│         │     scope: npm test                                       │
│         │                        ◀──── Return verdict ────┤         │
│         │                                                           │
│  "Aperture auto-approved npm test                                   │
│   based on your previous decisions."                                │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Tuning the learning speed

By default, Aperture needs 10 consistent human decisions at a 95% approval rate before auto-approving. You can adjust this:

**Via environment variables** (in your `.aperture.env` or shell):

```bash
APERTURE_PERMISSION_LEARNING_MIN_DECISIONS=5   # Fewer decisions needed
APERTURE_AUTO_APPROVE_THRESHOLD=0.90           # Lower approval rate required
```

**Via the MCP config** (per-project):

```json
{
  "mcpServers": {
    "aperture": {
      "type": "stdio",
      "command": "aperture",
      "args": ["mcp-serve"],
      "env": {
        "APERTURE_PERMISSION_LEARNING_MIN_DECISIONS": "5",
        "APERTURE_AUTO_APPROVE_THRESHOLD": "0.90"
      }
    }
  }
}
```

**Via the interactive wizard:**

```bash
aperture configure
```

## Running the API server alongside MCP

The MCP server (stdio) and REST API server can run at the same time. This is useful if you want to query the audit trail or permission patterns from a browser or script while Claude Code is running:

```bash
# In one terminal — API server for querying
aperture serve

# Claude Code uses MCP (stdio) — no extra terminal needed
```

Query examples:

```bash
# What has Aperture learned?
curl localhost:8100/permissions/patterns?min_decisions=5

# Full audit trail
curl localhost:8100/audit/events?limit=50

# Current config
curl localhost:8100/config
```

## Troubleshooting

**"aperture: command not found"**

Make sure the virtual environment where you installed Aperture is activated, or install it globally:

```bash
pip install -e ".[dev]"
which aperture   # Should print a path
```

**Permissions aren't being learned**

Check that `APERTURE_PERMISSION_LEARNING_ENABLED` is `true` (the default). Also verify decisions are being recorded:

```bash
curl localhost:8100/audit/events?limit=5
```

If the audit trail is empty, the MCP connection may not be working. Check Claude Code's MCP server status.

**Want to start fresh?**

Delete the database and re-initialize:

```bash
rm aperture.db
aperture init-db
```

## Next steps

- [Configuration reference](../README.md#configuration) — all environment variables
- [How decisions are made](../README.md#how-decisions-are-made) — the full resolution order
- [REST API examples](../README.md#rest-api) — query permissions, patterns, and audit trail programmatically
