# Aperture

The permission layer for AI agents. Controls what passes through.

Aperture sits between your organization and any AI agent runtime (Claude Code, OpenAI Agents SDK, Google ADK, LangChain, etc.). It doesn't run agents or make LLM calls — it decides what agents are allowed to do.

## Features

- **Permission Engine** — RBAC + ReBAC + auto-learning from human decisions
- **Artifact Store** — SHA-256 verified, immutable storage for every agent output
- **Audit Trail** — Append-only compliance log of every action
- **MCP Integration** — 9 tools for Claude Code via Model Context Protocol
- **REST API** — FastAPI server for any agent runtime

## Install

```bash
pip install -e ".[dev]"
```

Requires Python 3.12+.

## Quick Start

### As a CLI

```bash
# Initialize the database
aperture init-db

# Start the API server (default: localhost:8100)
aperture serve

# Start the MCP server (stdio, for Claude Code)
aperture mcp-serve
```

### As a library

```python
from aperture.permissions import PermissionEngine
from aperture.models import PermissionDecision

engine = PermissionEngine()

# Check if an action is allowed
verdict = engine.check("filesystem", "read", "src/main.py", rules=[])

# Record a human decision (feeds the learning engine)
engine.record_human_decision(
    tool="shell",
    action="execute",
    scope="npm test",
    decision=PermissionDecision.ALLOW,
    decided_by="user-1",
    organization_id="my-org",
)

# After enough decisions, the engine auto-approves similar actions
verdict = engine.check("shell", "execute", "npm test", rules=[])
print(verdict.decision)  # PermissionDecision.ALLOW (auto-learned)
```

### With Claude Code (MCP)

Add to your `.mcp.json`:

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

This exposes 9 tools to Claude Code:
- `check_permission` — Enriched permission check with risk assessment
- `approve_action` / `deny_action` — Record human decisions
- `explain_action` — Human-readable action explanation
- `get_permission_patterns` — View learned patterns
- `store_artifact` / `verify_artifact` — SHA-256 verified storage
- `get_cost_summary` — Token and cost breakdown
- `get_audit_trail` — Compliance audit trail

## API

Start the server with `aperture serve`, then:

```bash
# Check a permission
curl -X POST localhost:8100/permissions/check \
  -H "Content-Type: application/json" \
  -d '{"tool": "shell", "action": "execute", "scope": "rm -rf ./build/"}'

# Record a human decision
curl -X POST localhost:8100/permissions/record \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "shell",
    "action": "execute",
    "scope": "npm test",
    "decision": "allow",
    "decided_by": "user-1"
  }'

# Store an artifact
curl -X POST localhost:8100/artifacts/store \
  -H "Content-Type: application/json" \
  -d '{
    "task_id": "task-1",
    "artifact_type": "code",
    "content": "print(\"hello\")",
    "metadata": {"language": "python"}
  }'

# Query audit trail
curl localhost:8100/audit/events?limit=10
```

## Configuration

All settings via environment variables:

| Variable | Default | Description |
|---|---|---|
| `APERTURE_DB_BACKEND` | `sqlite` | `sqlite` or `postgres` |
| `APERTURE_DB_PATH` | `aperture.db` | SQLite file path |
| `APERTURE_POSTGRES_URL` | — | Postgres connection URL |
| `APERTURE_PERMISSION_LEARNING_ENABLED` | `true` | Auto-learn from human decisions |
| `APERTURE_PERMISSION_LEARNING_MIN_DECISIONS` | `10` | Min decisions before auto-deciding |
| `APERTURE_AUTO_APPROVE_THRESHOLD` | `0.95` | Allow rate to auto-approve |
| `APERTURE_AUTO_DENY_THRESHOLD` | `0.05` | Allow rate to auto-deny |
| `APERTURE_API_HOST` | `0.0.0.0` | API bind host |
| `APERTURE_API_PORT` | `8100` | API bind port |

## How It Works

1. An agent runtime asks Aperture: "Can this agent run `rm -rf ./build/`?"
2. Aperture checks RBAC rules, task-scoped grants (ReBAC), and learned patterns
3. If no rule matches, it returns `ask` — the human decides
4. The human's decision is recorded and used to learn patterns
5. After enough consistent decisions (default: 10), Aperture auto-decides
6. Every decision is logged to the immutable audit trail

No LLM calls. Every decision is deterministic — glob matching, database queries, statistics.

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
python -m pytest tests/ -v

# Run a specific test file
python -m pytest tests/test_permissions.py -v
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
