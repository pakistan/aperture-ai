# CLAUDE.md — Aperture

## What This Is

Aperture is the permission layer for AI agents. It controls what passes through.

It sits between enterprises and whatever AI agent runtimes they use (Claude Code, OpenAI Agents SDK, Google ADK, LangChain, etc.). It does not run agents. It does not make LLM calls. It does not care which model is on the other end.

Three core capabilities:
1. **Permission Engine** — Deterministic RBAC + ReBAC + learning from human decisions
2. **Artifact Persistence** — SHA-256 verified, immutable audit trail of every agent output
3. **Intelligence** — Cross-org anonymized signals with differential privacy

## Quick Start

```bash
cd aperture
source .venv312/bin/activate
aperture configure                # interactive setup wizard (writes .aperture.env)
aperture serve                    # start API server at localhost:8100
aperture mcp-serve                # start MCP server on stdio
aperture init-db                  # initialize database
python -m pytest tests/ -v        # run all tests
python examples/openclaw_demo.py  # run learning loop demo
```

## Tech Stack

- **Python 3.12** + **FastAPI** + **SQLModel** + **SQLite** (default)
- **MCP** (Model Context Protocol) for Claude Code integration
- Zero LLM calls anywhere in the codebase

## Project Structure

```
aperture/
├── aperture/
│   ├── api/                 # FastAPI routes
│   │   └── routes/
│   │       ├── permissions.py    # /permissions/* endpoints
│   │       ├── artifacts.py      # /artifacts/* endpoints
│   │       ├── audit.py          # /audit/* endpoints
│   │       └── intelligence.py   # /intelligence/* endpoints
│   ├── db/                  # Database engine (SQLite/Postgres)
│   ├── models/              # SQLModel table definitions + dataclasses
│   │   ├── permission.py    # Permission, PermissionLog, TaskPermission
│   │   ├── artifact.py      # Artifact with SHA-256 hashing
│   │   ├── audit.py         # AuditEvent (append-only)
│   │   ├── intelligence.py  # GlobalPermissionStat (cross-org DP stats)
│   │   └── verdict.py       # PermissionVerdict, RiskAssessment, OrgSignal, etc.
│   ├── permissions/         # Permission engine + learning + intelligence
│   │   ├── engine.py        # RBAC + ReBAC + auto-learning + verdict enrichment
│   │   ├── learning.py      # Pattern detection from decision history
│   │   ├── intelligence.py  # Cross-org DP intelligence engine
│   │   ├── risk.py          # OWASP-based risk classification
│   │   ├── crowd.py         # Org-level crowd signals
│   │   ├── similarity.py    # Taxonomy-based pattern similarity
│   │   ├── explainer.py     # Human-readable action explanations
│   │   └── resource.py      # Scope → resource normalization
│   ├── stores/              # Persistence layer
│   │   ├── artifact_store.py
│   │   └── audit_store.py
│   ├── config.py            # Settings via APERTURE_* env vars + runtime updates
│   ├── cli.py               # CLI entry point (serve | mcp-serve | init-db | configure)
│   └── mcp_server.py        # MCP server (11 tools, stdio transport)
├── examples/
│   ├── openclaw_demo.py     # Dual-mode demo (real OpenClaw or simulated)
│   ├── openclaw.json        # OpenClaw config wiring Aperture as MCP server
│   ├── openclaw_setup.sh    # Setup script for isolated demo workspace
│   └── system_prompt.md     # System prompt for Aperture-gated agent
├── tests/
├── main.py                  # Server entry point
└── pyproject.toml
```

## API Endpoints

### Permissions (`/permissions`)
- `POST /permissions/check` — Check if an action is permitted (with optional enrichment)
- `POST /permissions/record` — Record a human's decision (for learning)
- `POST /permissions/grant` — Grant task-scoped permission (ReBAC)
- `GET /permissions/patterns` — View learned patterns
- `GET /permissions/stats` — Decision statistics
- `GET /permissions/similar` — Find similar permission patterns
- `GET /permissions/explain` — Get human-readable action explanation with risk

### Artifacts (`/artifacts`)
- `POST /artifacts/store` — Store with automatic SHA-256 verification
- `GET /artifacts/costs/summary` — Cost breakdown by provider/model
- `GET /artifacts/task/{task_id}` — List artifacts by task
- `GET /artifacts/{id}` — Retrieve artifact
- `POST /artifacts/{id}/verify` — Re-verify integrity

### Audit (`/audit`)
- `GET /audit/events` — Query with filters
- `GET /audit/events/{id}` — Single event detail
- `GET /audit/entity/{type}/{id}` — Entity history
- `GET /audit/count` — Total event count

### Config (`/config`)
- `GET /config` — Current tunable settings and descriptions
- `PATCH /config` — Update tunable settings at runtime (persists to `.aperture.env`)

### Intelligence (`/intelligence`)
- `GET /intelligence/global-signal` — Cross-org DP-protected permission signal

## MCP Tools

11 tools exposed via MCP (stdio transport):
- `check_permission` — Enriched permission check with risk, explanation, crowd signal
- `approve_action` / `deny_action` — Record human decisions (feeds learning + intelligence)
- `explain_action` — Human-readable explanation with risk assessment
- `get_permission_patterns` — View learned auto-approve/deny patterns
- `store_artifact` / `verify_artifact` — SHA-256 verified artifact storage
- `get_cost_summary` — Token and cost breakdown
- `get_audit_trail` — Compliance audit trail
- `get_config` — Read tunable configuration settings
- `update_config` — Update configuration at runtime (persists to `.aperture.env`)

## Architecture Rules

1. **Zero LLM calls.** Every decision is deterministic — glob matching, database queries, statistics.
2. **Append-only audit.** AuditEvents are never deleted or modified.
3. **SHA-256 everything.** Every artifact is hashed on storage. Integrity re-verifiable at any time.
4. **Fire-and-forget logging.** Audit/logging never breaks the primary operation.
5. **Provider agnostic.** The `runtime_id` field tracks which external runtime produced an artifact, but Aperture never calls any LLM.
6. **Differential privacy.** Cross-org intelligence uses RAPPOR-style local DP. True decisions never leave the org.

## Configuration

Config precedence (highest first):
1. Shell env vars (`export APERTURE_*=...`) — always win
2. `.aperture.env` file values (written by `aperture configure` or `PATCH /config`)
3. Defaults in Settings class

Run `aperture configure` for an interactive setup wizard, or use `PATCH /config` at runtime.

### All settings (`APERTURE_*` env vars)

| Variable | Default | Tunable? | Description |
|---|---|---|---|
| `APERTURE_DB_BACKEND` | `sqlite` | No | `sqlite` or `postgres` |
| `APERTURE_DB_PATH` | `aperture.db` | No | SQLite file path |
| `APERTURE_POSTGRES_URL` | `` | No | Postgres connection URL |
| `APERTURE_PERMISSION_LEARNING_ENABLED` | `true` | Yes | Auto-learn from human decisions |
| `APERTURE_PERMISSION_LEARNING_MIN_DECISIONS` | `10` | Yes | Min decisions before auto-deciding |
| `APERTURE_AUTO_APPROVE_THRESHOLD` | `0.95` | Yes | Approval rate to auto-approve |
| `APERTURE_AUTO_DENY_THRESHOLD` | `0.05` | Yes | Approval rate to auto-deny |
| `APERTURE_INTELLIGENCE_ENABLED` | `false` | Yes | Enable cross-org DP intelligence (opt-in) |
| `APERTURE_INTELLIGENCE_EPSILON` | `1.0` | Yes | DP noise level (higher = less private) |
| `APERTURE_INTELLIGENCE_MIN_ORGS` | `5` | Yes | Min orgs before surfacing global signal |
| `APERTURE_ARTIFACT_STORAGE_DIR` | `` | No | Artifact file storage directory |
| `APERTURE_API_HOST` | `0.0.0.0` | No | API server bind host |
| `APERTURE_API_PORT` | `8100` | No | API server port |

"Tunable" settings can be updated at runtime via `PATCH /config`, the CLI wizard, or MCP `update_config` tool. Infrastructure settings (No) require restart.

## OpenClaw Integration

Aperture integrates with [OpenClaw (ClawDBot)](https://github.com/clawdbot/openclaw) as an MCP server. OpenClaw is an open-source AI agent that supports MCP tool servers.

### Quick Start (with OpenClaw)

```bash
# Prerequisites
npm install -g openclaw@latest      # install OpenClaw
cd aperture && pip install -e .      # install Aperture

# Option A: Setup script
bash examples/openclaw_setup.sh
cd /tmp/aperture-openclaw-demo && openclaw chat

# Option B: Python demo (auto-detects OpenClaw)
python examples/openclaw_demo.py

# Option C: Simulated mode (no OpenClaw needed)
python examples/openclaw_demo.py --sim
```

### How It Works

1. `examples/openclaw.json` wires Aperture as an MCP server with fast-learning thresholds (3 decisions, 80% threshold)
2. `examples/system_prompt.md` instructs the agent to call `check_permission` before every action
3. The agent asks to read a file -> Aperture denies (no history)
4. User approves 3 times -> Aperture learns the pattern
5. Agent asks to read another file -> Aperture auto-approves

### Config Files

| File | Purpose |
|------|---------|
| `examples/openclaw.json` | MCP server config (points Aperture at an isolated DB) |
| `examples/system_prompt.md` | Instructs the agent to gate all actions through Aperture |
| `examples/openclaw_setup.sh` | Creates `/tmp/aperture-openclaw-demo/` with fresh DB |
