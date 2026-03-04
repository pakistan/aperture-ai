# Setting Up AIperture with Claude Code

This guide walks you through adding AIperture as Claude Code's permission layer via MCP (Model Context Protocol). After setup, Claude Code will check permissions through AIperture before taking actions, and AIperture will learn your preferences over time.

## Prerequisites

- Python 3.12+
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) installed

## Step 1: Install AIperture

```bash
pip install aiperture
```

Verify it installed:

```bash
aiperture --help
```

## Step 2: Set up AIperture for Claude Code

```bash
aiperture setup-claude --bootstrap=developer
```

This does four things:
1. Creates `.mcp.json` in your project with the AIperture MCP server config
2. Adds Claude Code hooks to `.claude/settings.json` (PermissionRequest + PostToolUse)
3. Initializes the database (`aiperture.db`)
4. Pre-seeds 75 safe patterns (git, file reads, test runners, linters)

Options:
- `--global` — install to `~/.claude/.mcp.json` (applies to all projects)
- `--bootstrap=readonly` — 48 read-only patterns instead of the full developer set
- No `--bootstrap` — clean slate, learn everything from scratch

If you already have a `.mcp.json`, AIperture is added alongside your existing MCP servers.

<details>
<summary>Manual setup (without setup-claude)</summary>

```bash
aiperture init-db
```

Add to your `.mcp.json` (project root or `~/.claude/`):

```json
{
  "mcpServers": {
    "aiperture": {
      "type": "stdio",
      "command": "aiperture",
      "args": ["mcp-serve"]
    }
  }
}
```

Optionally bootstrap: `aiperture bootstrap developer`

</details>

## Step 3: Start the AIperture server

AIperture has two servers that work differently:

| | MCP server | HTTP API server |
|---|---|---|
| **Started by** | Claude Code (automatic via `.mcp.json`) | You (`aiperture serve`) |
| **Transport** | stdio (built into Claude Code's process) | HTTP on `localhost:8100` |
| **What it does** | Exposes 10 MCP tools (check_permission, etc.) | Handles hooks + REST API queries |
| **If not running** | Claude Code shows MCP connection error | Hooks silently fail, Claude Code shows normal prompts |

The **MCP server** starts automatically when Claude Code launches — you don't need to do anything.

The **HTTP server** must be started separately for hooks to work:

```bash
aiperture serve
```

Leave this running in a terminal (or run it as a background service). If you don't run it, hooks are inactive but everything else still works — you just won't get hook-based auto-approval, and the MCP path functions on its own.

## Step 4: Start using Claude Code

Restart Claude Code (or open a new session) and AIperture is active. Two integration paths work simultaneously:

### Hook integration (recommended, zero-friction)

AIperture hooks into Claude Code's native permission flow via HTTP hooks. No double-prompting — it works silently:

1. **Claude wants to run a tool** — e.g., `Bash("npm test")`
2. **PermissionRequest hook fires** — AIperture checks if it has a learned ALLOW pattern
3. **If learned: auto-approved** — The permission dialog never appears. Tool runs immediately.
4. **If not learned: normal prompt** — You see Claude Code's standard "Allow?" dialog
5. **PostToolUse hook fires** — Records your approval for learning
6. **After enough approvals** — AIperture starts auto-approving via step 3

### MCP integration (for other runtimes)

AIperture also runs as an MCP server with 10 read-only tools. This path is used by non-Claude runtimes (OpenAI Agents SDK, LangChain, etc.) and provides permission checking, artifact storage, and audit trail access. Decision recording (`approve_action`, `deny_action`) and revocation are only available via the HTTP API, where a human-controlled UI sits between check and approve.

### What to expect on first use

When you start your first Claude Code session with AIperture:

1. **AIperture hooks are active** — PermissionRequest and PostToolUse events are sent to AIperture's HTTP endpoints before and after each tool call.

2. **Everything starts as "ask"** — AIperture has no history yet, so it returns no opinion and Claude Code shows its normal permission prompts.

3. **You approve the safe stuff** — When Claude Code shows "Allow?", say yes for things like `git status`, `cat README.md`, `npm test`. Say no for anything you wouldn't want an agent doing unsupervised.

4. **AIperture learns your preferences** — After 10 consistent approvals of the same action type (e.g., `filesystem.read`), AIperture auto-approves it going forward. The permission prompt stops appearing.

5. **Dangerous actions stay flagged** — `rm -rf`, shell commands with broad wildcards, anything touching system paths — these are scored as HIGH/CRITICAL risk and always require your explicit approval, even with a learned pattern.

This is what it looks like in practice:

| MCP Tool | What it does |
|------|-------------|
| `check_permission` | Check if an action is allowed (with risk assessment and HMAC challenge) |
| `explain_action` | Get a human-readable explanation of what an action does |
| `get_permission_patterns` | View what AIperture has learned from your decisions |
| `get_compliance_report` | See which tool executions had prior permission checks |
| `list_auto_approved_patterns` | See all patterns currently being auto-approved |
| `store_artifact` | Store an agent output with SHA-256 verification |
| `verify_artifact` | Verify an artifact's integrity |
| `get_cost_summary` | Get token and cost breakdown |
| `get_audit_trail` | Query the compliance audit trail |
| `get_config` | View current AIperture settings |

**Not available via MCP** (HTTP API only): `approve_action`, `deny_action`, `revoke_permission_pattern`, `report_tool_execution`. These are excluded because an MCP caller (the AI agent) could relay HMAC tokens to self-approve without human involvement. Use hooks for Claude Code, or the HTTP API for runtimes with their own UI.

## AIperture vs Claude Code's built-in permissions

Claude Code has its own permission system — the "Allow once / Allow for session / Always allow / Deny" popup. With hooks, AIperture integrates directly into this flow:

| | Claude Code built-in | AIperture (hooks) |
|---|---|---|
| **What it controls** | Whether Claude can call a tool at all | Whether the *action* (read this file, run this command) is allowed |
| **Persistence** | Per-session or permanent per-machine | Per-database, shared across sessions, learns over time |
| **Learning** | No — same prompts every new session | Yes — auto-approves after enough consistent human decisions |
| **Audit trail** | No | Yes — every decision logged with hash-chained integrity |
| **Risk scoring** | No | Yes — LOW/MEDIUM/HIGH/CRITICAL per action |
| **User experience** | Prompt appears every time | Prompt disappears after AIperture learns the pattern |

With hooks, AIperture works *within* Claude Code's permission flow — not alongside it. The PermissionRequest hook auto-approves learned patterns before the prompt appears, so you never see it. For unknown patterns, Claude Code shows its normal prompt and AIperture learns from your decision.

**Important:** AIperture only checks permissions for tool calls that access external resources (files, shell, APIs). It does NOT interfere with Claude asking you questions, presenting options, or having a normal conversation. Those happen without involving AIperture at all.

## How the learning loop works

### Hook-based flow (recommended)

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  Claude Code                     AIperture Server                    │
│  ───────────                     ───────────────                    │
│                                                                     │
│  Claude wants to run "npm test"                                     │
│         │                                                           │
│         ├── PermissionRequest ────▶  No history. Return {}          │
│         │   hook fires                (no opinion)                  │
│         │                       ◀────────────────────────┤          │
│         │                                                           │
│  User sees normal Claude Code prompt: "Allow npm test?"             │
│         │                                                           │
│  User:  "Yes, allow"                                                │
│         │                                                           │
│  Tool executes successfully                                         │
│         │                                                           │
│         ├── PostToolUse ──────────▶  Recorded approval. (1 of 10)   │
│         │   hook fires                                              │
│         │                                                           │
│         │     ... 9 more approvals over time ...                    │
│         │                                                           │
│         ├── PermissionRequest ────▶  10/10 approvals at 100%.       │
│         │   hook fires                Return auto-approve.          │
│         │                       ◀────────────────────────┤          │
│         │                                                           │
│  Permission dialog NEVER appears.                                   │
│  Tool runs immediately.                                             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### MCP-based flow (for other runtimes)

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  AI Agent                        AIperture (MCP)                     │
│  ────────                        ──────────────                     │
│                                                                     │
│  "I need to run npm test"                                           │
│         │                                                           │
│         ├──── check_permission ────▶  No history for this action.   │
│         │     tool: shell              Decision: ASK                │
│         │     action: execute          + HMAC challenge             │
│         │     scope: npm test    ◀──── Return verdict ────┤         │
│         │                                                           │
│  "Permission needed. Approve?"                                      │
│         │                                                           │
│  User:  "Yes"                                                       │
│         │                                                           │
│         ├──── approve_action ─────▶  Recorded. (1 of 10 needed)     │
│         │     + challenge token        (HMAC verified)              │
│         │                                                           │
│         │     ... 9 more approvals over time ...                    │
│         │                                                           │
│         ├──── check_permission ────▶  10/10 approvals at 100%.      │
│         │     tool: shell              Decision: ALLOW              │
│         │     action: execute          Decided by: auto_learned     │
│         │     scope: npm test    ◀──── Return verdict ────┤         │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Skip the first-session approval flood

By default, AIperture asks about everything on first use. You can pre-seed safe patterns using bootstrap presets:

```bash
aiperture bootstrap developer    # 75 patterns: git, file reads, test runners, linters
aiperture bootstrap readonly     # 48 patterns: file reads and safe shell commands only
aiperture bootstrap minimal      # Clean slate (default behavior)
```

After bootstrapping, common actions like `git status`, `cat README.md`, and `npm test` are auto-approved immediately.

## Revoking learned patterns

If AIperture learned to auto-approve something you no longer want:

```bash
aiperture revoke shell execute "rm*"     # Revoke all rm-related auto-approvals
```

Or use the HTTP API: `curl -X POST localhost:8100/permissions/revoke -d '{"tool":"shell","action":"execute","scope":"rm*","revoked_by":"admin"}'`. The pattern immediately requires fresh human decisions. Revoked records are preserved in the audit trail.

## Tuning the learning speed

By default, AIperture needs 10 consistent human decisions at a 95% approval rate before auto-approving. You can adjust this:

**Via environment variables** (in your `.aiperture.env` or shell):

```bash
AIPERTURE_PERMISSION_LEARNING_MIN_DECISIONS=5   # Fewer decisions needed
AIPERTURE_AUTO_APPROVE_THRESHOLD=0.90           # Lower approval rate required
```

**Via the MCP config** (per-project):

```json
{
  "mcpServers": {
    "aiperture": {
      "type": "stdio",
      "command": "aiperture",
      "args": ["mcp-serve"],
      "env": {
        "AIPERTURE_PERMISSION_LEARNING_MIN_DECISIONS": "5",
        "AIPERTURE_AUTO_APPROVE_THRESHOLD": "0.90"
      }
    }
  }
}
```

**Via the interactive wizard:**

```bash
aiperture configure
```

## Security features active by default

AIperture includes several security hardening features that are active out of the box:

- **Rate limiting** — 200 permission checks/minute per session (configurable via `AIPERTURE_RATE_LIMIT_PER_MINUTE`)
- **Session risk scoring** — Cumulative risk budget of 50.0 per session. Many individually-safe actions that compound are escalated to ASK. (configurable via `AIPERTURE_SESSION_RISK_BUDGET`)
- **Sensitive path protection** — Files matching patterns like `*secret*`, `*.env`, `*.pem`, `*.key` skip scope normalization and require exact-match learning
- **Temporal decay** — Auto-learned patterns expire after 90 days without human reconfirmation (configurable via `AIPERTURE_PATTERN_MAX_AGE_DAYS`)
- **Rubber-stamping detection** — Rapid approvals (5+ within 60s) are excluded from the learning engine
- **Hash-chained audit trail** — Every audit event is cryptographically chained for tamper detection
- **HMAC nonce persistence** — Challenge nonces survive server restarts, preventing replay attacks

## Querying the API server

With `aiperture serve` running (see Step 3), you can query the REST API from a browser or script:

Query examples:

```bash
# Check database health
curl localhost:8100/health

# What has AIperture learned?
curl localhost:8100/permissions/patterns?min_decisions=5

# Full audit trail
curl localhost:8100/audit/events?limit=50

# Verify audit trail integrity (hash chain)
curl localhost:8100/audit/verify-chain

# Prometheus metrics (for monitoring dashboards)
curl localhost:8100/metrics

# Current config
curl localhost:8100/config
```

### Securing the API server

If the API server is accessible on a network (not just localhost), set a bearer token:

```bash
export AIPERTURE_API_KEY="your-secret-key"
aiperture serve
```

All requests must then include `Authorization: Bearer your-secret-key`. The MCP server is unaffected — it uses stdio transport and doesn't go through the HTTP API.

## Viewing logs

Claude Code spawns `aiperture mcp-serve` automatically, so stderr logs are invisible. To see what AIperture is doing, enable file logging:

```json
{
  "mcpServers": {
    "aiperture": {
      "type": "stdio",
      "command": "aiperture",
      "args": ["mcp-serve"],
      "env": {
        "AIPERTURE_LOG_FILE": "~/.aiperture/aiperture.log"
      }
    }
  }
}
```

Then in a separate terminal:

```bash
tail -f ~/.aiperture/aiperture.log
```

Logs rotate automatically at 5 MB with 3 backups.

## Hook configuration details

`aiperture setup-claude` writes the following hooks to `.claude/settings.json`:

```json
{
  "hooks": {
    "PermissionRequest": [{
      "matcher": "^(?!mcp__aiperture__).*",
      "hooks": [{"type": "http", "url": "http://localhost:8100/hooks/permission-request"}]
    }],
    "PostToolUse": [{
      "matcher": "^(?!mcp__aiperture__).*",
      "hooks": [{"type": "http", "url": "http://localhost:8100/hooks/post-tool-use"}]
    }]
  }
}
```

Key details:
- The `matcher` regex excludes AIperture's own MCP tools (`mcp__aiperture__*`) to prevent recursive loops
- **PermissionRequest** fires when Claude Code is about to show a permission dialog. AIperture can auto-approve or auto-deny based on learned patterns.
- **PostToolUse** fires after a tool executes successfully. AIperture records this as an implicit approval for learning.
- If the server is down, the HTTP hooks fail with a non-2xx response, and Claude Code falls back to its normal permission prompts (fail-open)
- HIGH/CRITICAL risk actions are never auto-approved via hooks, even with a learned pattern

To remove hooks: `aiperture remove-claude` cleans up both MCP config and hook entries.

## Troubleshooting

**"aiperture: command not found"**

```bash
pip install aiperture
which aiperture   # Should print a path
```

If you're using a virtual environment, make sure it's activated. If you installed globally, make sure your Python scripts directory is on your PATH.

**Hooks aren't working (still seeing every permission prompt)**

Make sure the API server is running: `aiperture serve`. Check that hooks are in `.claude/settings.json`:

```bash
cat .claude/settings.json | jq .hooks
```

If missing, re-run `aiperture setup-claude`. Also check the server logs for incoming hook requests.

**Permissions aren't being learned**

Check that `AIPERTURE_PERMISSION_LEARNING_ENABLED` is `true` (the default). Also verify decisions are being recorded:

```bash
curl localhost:8100/audit/events?limit=5
```

If the audit trail is empty, the MCP connection may not be working. Check Claude Code's MCP server status.

**Want to start fresh?**

Delete the database and re-initialize:

```bash
rm aiperture.db
aiperture init-db
```

## Next steps

- [Configuration reference](../README.md#configuration) — all environment variables
- [How decisions are made](../README.md#how-decisions-are-made) — the full resolution order
- [REST API examples](../README.md#rest-api) — query permissions, patterns, and audit trail programmatically
