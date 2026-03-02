# Setting Up Aperture with OpenClaw

This guide walks you through wiring Aperture as the permission layer for [OpenClaw](https://github.com/ClawDBot/openclaw), an open-source AI agent runtime. After setup, OpenClaw will check every tool call through Aperture, and Aperture will learn your approval patterns over time.

## Prerequisites

- Python 3.12+
- Node.js 18+ (for OpenClaw)

## Step 1: Install both tools

```bash
npm install -g openclaw@latest      # OpenClaw
```

```bash
pip install aperture-ai             # Aperture
```

Verify both installed:

```bash
openclaw --version
aperture --help
```

## Step 2: Initialize Aperture

```bash
aperture init-db
```

## Step 3: Create the OpenClaw config

Create `openclaw.json` in your project root:

```json
{
  "mcpServers": {
    "aperture": {
      "command": "aperture",
      "args": ["mcp-serve"],
      "env": {
        "APERTURE_DB_PATH": "./aperture.db",
        "APERTURE_PERMISSION_LEARNING_MIN_DECISIONS": "3",
        "APERTURE_AUTO_APPROVE_THRESHOLD": "0.80"
      }
    }
  }
}
```

> **Why the low thresholds?** `3` decisions and `0.80` approval rate let you see the learning loop in action quickly. For real use, bump these to the defaults (`10` decisions, `0.95` threshold) or run `aperture configure` to tune them.

## Step 4: Add the system prompt

Create `system_prompt.md` in the same directory. This tells OpenClaw how to use Aperture's tools:

```markdown
# Aperture Permission System

You have access to the Aperture permission layer via MCP tools.
You MUST follow these rules for every action you take.

## Before Every Action

Before using any tool (reading files, running commands, making API calls),
call `check_permission` first:

    check_permission(tool="filesystem", action="read", scope="README.md")

## Handling the Verdict

- **"allow"**: Proceed with the action.
- **"deny"**: Do NOT proceed. Tell the user and ask if they want to approve it.
- **"ask"**: Do NOT proceed. Show the risk assessment and ask for approval.

## When the User Approves

Call `approve_action` with the same tool/action/scope, then proceed.

## When the User Denies

Call `deny_action` with the same tool/action/scope. Do NOT proceed.

## Tool Categories

| Tool         | Action    | Example Scope                    |
|-------------|-----------|----------------------------------|
| `filesystem` | `read`    | `README.md`, `src/*.py`          |
| `filesystem` | `write`   | `output.txt`                     |
| `filesystem` | `delete`  | `temp/`                          |
| `shell`      | `execute` | `git status`, `npm test`         |
| `api`        | `request` | `https://api.example.com`        |
```

A complete version is available at [`examples/system_prompt.md`](../examples/system_prompt.md).

## Step 5: Start chatting

```bash
openclaw chat
```

## What the learning loop looks like

Here's what happens in a typical session:

### First time — Aperture denies (no history)

```
You:    "Read the file README.md"

Agent:  → check_permission(tool="filesystem", action="read", scope="README.md")
        ← Decision: DENY
        ← Risk: LOW (score: 0.06)
        ← Explanation: "Read file README.md from the filesystem"

Agent:  "Aperture denied this action (no prior history). It's low risk —
         want me to approve it?"

You:    "Yes"

Agent:  → approve_action(tool="filesystem", action="read", scope="README.md")
        ← Recorded (1 of 3 needed for auto-approve)
```

### Second and third time — still asking, but counting

```
You:    "Now read src/main.py"

Agent:  → check_permission(tool="filesystem", action="read", scope="src/main.py")
        ← Decision: DENY

Agent:  "Still needs approval. Approve?"

You:    "Yes"

Agent:  → approve_action(...)
        ← Recorded (2 of 3)
```

Repeat once more...

### Fourth time — auto-approved

```
You:    "Read package.json"

Agent:  → check_permission(tool="filesystem", action="read", scope="package.json")
        ← Decision: ALLOW
        ← Decided by: auto_learned

Agent:  "Aperture auto-approved this based on your previous decisions.
         Reading package.json now..."
```

### Dangerous actions — always flagged

```
You:    "Delete the build directory"

Agent:  → check_permission(tool="filesystem", action="delete", scope="build/")
        ← Decision: DENY
        ← Risk: HIGH (score: 0.63)
        ← Factors: ["high_severity_action"]

Agent:  "Aperture flagged this as HIGH risk. Do you want to approve it?"
```

## Checking what Aperture learned

Ask the agent:

```
You:    "Show me what Aperture has learned"

Agent:  → get_permission_patterns(min_decisions=3, organization_id="default")

Agent:  "Aperture has learned 2 patterns:
         - filesystem.read: 100% approval rate (4 decisions) → auto-approve
         - shell.execute on 'git status': 100% approval (3 decisions) → auto-approve"
```

Or query the REST API directly (if `aperture serve` is running):

```bash
curl localhost:8100/permissions/patterns?min_decisions=3
```

## Quick demo (no OpenClaw needed)

If you just want to see the learning loop without installing OpenClaw:

```bash
python examples/openclaw_demo.py --sim
```

This runs the full deny → approve → auto-approve cycle in-process using Aperture's API.

Or use the setup script for a full isolated workspace:

```bash
bash examples/openclaw_setup.sh
```

## Production settings

For real use, update your `openclaw.json` env or `.aperture.env`:

| Setting | Demo | Production | Why |
|---------|------|------------|-----|
| `MIN_DECISIONS` | `3` | `10` | More decisions = higher confidence |
| `AUTO_APPROVE_THRESHOLD` | `0.80` | `0.95` | Stricter threshold = fewer false auto-approves |
| `AUTO_DENY_THRESHOLD` | `0.05` | `0.05` | Same — deny only on strong consensus |

```json
{
  "env": {
    "APERTURE_PERMISSION_LEARNING_MIN_DECISIONS": "10",
    "APERTURE_AUTO_APPROVE_THRESHOLD": "0.95",
    "APERTURE_AUTO_DENY_THRESHOLD": "0.05"
  }
}
```

## Troubleshooting

**"openclaw: command not found"**

```bash
npm install -g openclaw@latest
```

**"aperture: command not found"**

Make sure the virtual environment where you installed Aperture is activated:

```bash
which aperture   # Should print a path
```

**Agent isn't calling check_permission**

The system prompt is what tells OpenClaw to use Aperture's tools. Make sure `system_prompt.md` is in the same directory and your OpenClaw config references it.

**Want to start fresh?**

```bash
rm aperture.db
aperture init-db
```

## Next steps

- [Configuration reference](../README.md#configuration) — all environment variables
- [How decisions are made](../README.md#how-decisions-are-made) — the full resolution order
- [Setting up with Claude Code](setup-claude-code.md) — if you also use Claude Code
