# CLAUDE.md — AIperture

## What This Is

AIperture is the permission layer for AI agents. It controls what passes through.

It sits between enterprises and whatever AI agent runtimes they use (Claude Code, OpenAI Agents SDK, Google ADK, LangChain, etc.). It does not run agents. It does not make LLM calls. It does not care which model is on the other end.

Three core capabilities:
1. **Permission Engine** — Deterministic RBAC + ReBAC + learning from human decisions
2. **Artifact Persistence** — SHA-256 verified, immutable audit trail of every agent output
3. **Intelligence** — Cross-org anonymized signals with differential privacy

## Quick Start

```bash
cd aiperture
source .venv312/bin/activate
aiperture configure                # interactive setup wizard (writes .aiperture.env)
aiperture serve                    # start API server at localhost:8100
aiperture mcp-serve                # start MCP server on stdio
aiperture init-db                  # initialize database
python -m pytest tests/ -v        # run all tests
python examples/openclaw_demo.py  # run learning loop demo
```

## Tech Stack

- **Python 3.12** + **FastAPI** + **SQLModel** + **SQLite** (default)
- **MCP** (Model Context Protocol) for Claude Code integration
- Zero LLM calls anywhere in the codebase

## Project Structure

```
aiperture/
├── aiperture/
│   ├── api/                 # FastAPI routes
│   │   ├── auth.py              # Bearer token auth (AIPERTURE_API_KEY) + plugin auth_backend
│   │   ├── app.py               # FastAPI app factory + plugin loading
│   │   └── routes/
│   │       ├── permissions.py    # /permissions/* endpoints
│   │       ├── artifacts.py      # /artifacts/* endpoints
│   │       ├── audit.py          # /audit/* endpoints + /audit/verify-chain (hash chain integrity)
│   │       ├── config.py         # /config endpoints (GET + PATCH runtime tuning)
│   │       ├── health.py         # /health endpoint (DB + plugin health checkers)
│   │       ├── intelligence.py   # /intelligence/* endpoints
│   │       └── metrics.py        # /metrics endpoint (Prometheus format)
│   ├── db/                  # Database engine (SQLite/Postgres) + plugin db_engine
│   ├── models/              # SQLModel table definitions + dataclasses
│   │   ├── permission.py    # Permission, PermissionLog, TaskPermission, ConsumedNonce
│   │   ├── artifact.py      # Artifact with SHA-256 hashing
│   │   ├── audit.py         # AuditEvent (append-only, hash-chained)
│   │   ├── intelligence.py  # GlobalPermissionStat (cross-org DP stats)
│   │   └── verdict.py       # PermissionVerdict, RiskAssessment, OrgSignal, etc.
│   ├── permissions/         # Permission engine + learning + intelligence
│   │   ├── engine.py        # RBAC + ReBAC + auto-learning + rate limiting + risk budget + rubber-stamping + temporal decay + metrics
│   │   ├── learning.py      # Pattern detection from decision history
│   │   ├── intelligence.py  # Cross-org DP intelligence + plugin intelligence_backend
│   │   ├── risk.py          # OWASP-based risk classification + plugin risk_rules
│   │   ├── crowd.py         # Org-level crowd signals
│   │   ├── similarity.py    # Taxonomy-based pattern similarity
│   │   ├── explainer.py     # Human-readable action explanations
│   │   ├── resource.py      # Scope → resource normalization
│   │   ├── challenge.py     # HMAC challenge-response + DB-persisted nonce replay protection
│   │   ├── presets.py       # Bootstrap presets (developer, readonly, minimal)
│   │   └── scope_normalize.py # Scope normalization for learning
│   ├── stores/              # Persistence layer
│   │   ├── artifact_store.py
│   │   └── audit_store.py   # Hash-chained writes + verify_chain() + plugin audit_hook
│   ├── metrics.py           # Prometheus counters, histograms, gauges for observability
│   ├── plugins.py           # Plugin registry + Protocol definitions (open-core)
│   ├── config.py            # Settings via AIPERTURE_* env vars + plugin config
│   ├── cli.py               # CLI entry point (serve | mcp-serve | init-db | configure | bootstrap | revoke)
│   └── mcp_server.py        # MCP server (14 tools, stdio transport) + plugin mcp_tools
├── docs/
│   └── plugins.md           # Plugin development guide
├── examples/
│   ├── openclaw_demo.py     # Dual-mode demo (real OpenClaw or simulated)
│   ├── openclaw.json        # OpenClaw config wiring AIperture as MCP server
│   ├── openclaw_setup.sh    # Setup script for isolated demo workspace
│   └── system_prompt.md     # System prompt for AIperture-gated agent
├── tests/
├── main.py                  # Server entry point
└── pyproject.toml
```

## API Endpoints

### Health (`/health`)
- `GET /health` — Database connectivity probe (returns `healthy` or `degraded` with details)

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
- `GET /audit/verify-chain` — Verify hash chain integrity (tamper detection)

### Config (`/config`)
- `GET /config` — Current tunable settings and descriptions
- `PATCH /config` — Update tunable settings at runtime (persists to `.aiperture.env`)

### Intelligence (`/intelligence`)
- `GET /intelligence/global-signal` — Cross-org DP-protected permission signal

### Metrics (`/metrics`)
- `GET /metrics` — Prometheus-compatible metrics (counters, histograms, gauges)

## MCP Tools

14 tools exposed via MCP (stdio transport):

### Permission tools
- `check_permission` — Enriched permission check with risk, explanation, crowd signal, HMAC challenge
- `approve_action` / `deny_action` — Record human decisions (requires valid HMAC challenge token)
- `explain_action` — Human-readable explanation with risk assessment
- `get_permission_patterns` — View learned auto-approve/deny patterns

### Compliance tools
- `report_tool_execution` — Report that an agent executed a tool (for compliance tracking)
- `get_compliance_report` — Compare executions vs permission checks to find compliance gaps

### Revocation tools
- `revoke_permission_pattern` — Revoke auto-approval for a (tool, action, scope) pattern
- `list_auto_approved_patterns` — List all patterns currently being auto-approved

### Artifact tools
- `store_artifact` / `verify_artifact` — SHA-256 verified artifact storage
- `get_cost_summary` — Token and cost breakdown

### Audit & config tools
- `get_audit_trail` — Compliance audit trail
- `get_config` — Read tunable configuration settings

## Security Architecture

1. **HTTP API authentication** — Optional bearer token auth via `AIPERTURE_API_KEY` env var. When set, all HTTP API routes require `Authorization: Bearer <key>`. MCP server (stdio) is unaffected. When unset, open access for local development.
2. **HMAC challenge-response** — Every non-ALLOW verdict includes a cryptographic challenge token (HMAC-SHA256 signed with a server-side secret in `challenge.py`). `approve_action`/`deny_action` require a valid challenge, preventing agents from self-approving without human involvement.
3. **No config mutation via MCP** — The `update_config` MCP tool was removed. Agents can read config (`get_config`) but cannot lower thresholds. Config changes require the CLI wizard or HTTP API.
4. **Deep risk analysis** — `risk.py` unpacks shell wrappers (`bash -c`, `sudo`), pipe-to-exec (`curl | sh`), scripting oneliners (`python -c "os.system(...)"`), and `find -exec`. Inner command risk is what counts. Recursion depth is capped at 5 levels to prevent DoS. HIGH/CRITICAL actions are never auto-approved.
5. **Fail-closed circuit breaker** — If the database becomes unavailable during a permission check, the engine fails closed (defaults to deny). The `GET /health` endpoint probes database connectivity.
6. **Compliance tracking** — `report_tool_execution` records tool executions. `get_compliance_report` compares executions against permission checks to find unchecked tool usage.
7. **Bootstrap presets** — `presets.py` provides `developer` (75 patterns), `readonly` (48), `minimal` (0) to reduce first-session approval fatigue.
8. **Content awareness** — `content_hash` parameter in `check_permission` differentiates writes by content. Session cache key is a 5-tuple: `(tool, action, scope, session_id, content_hash)`.
9. **Scope normalization** — `scope_normalize.py` groups command variants (e.g., `git log --oneline -5` → `git log*`) for faster learning.
10. **Revocation** — `engine.revoke_pattern()` soft-deletes decisions via `revoked_at` timestamp. Excluded from learning, crowd signals, and pattern detection. Preserved for audit.
11. **Rate limiting** — Per-session rate limiter (`AIPERTURE_RATE_LIMIT_PER_MINUTE`, default 200). In-memory counter with 1-minute sliding window. Exceeding returns DENY with `rate_limit_exceeded` factor. Prevents DoS and permission enumeration.
12. **Cumulative session risk scoring** — Tracks cumulative risk per session (`AIPERTURE_SESSION_RISK_BUDGET`, default 50.0). When exhausted, all subsequent checks escalate to ASK regardless of learned patterns. Prevents "death by a thousand cuts" data exfiltration.
13. **Sensitive path protection** — `AIPERTURE_SENSITIVE_PATTERNS` (configurable glob list) skips scope normalization for sensitive files (secrets, credentials, keys, .env). Requires exact-match learning instead of wildcard patterns.
14. **Temporal pattern decay** — `AIPERTURE_PATTERN_MAX_AGE_DAYS` (default 90). Auto-learned patterns expire if the most recent human decision is older than the configured age. Forces periodic re-confirmation.
15. **Rubber-stamping detection** — Tracks approval velocity per `(session_id, tool, action)`. If 5+ approvals within 60s (configurable), flags with `:rapid` suffix. Rapid decisions are excluded from learning engine calculations.
16. **HMAC nonce persistence** — `ConsumedNonce` SQLModel table persists used nonces to database. In-memory cache as first-level check, DB as fallback. Closes replay attack window across server restarts.
17. **Hash-chained audit trail** — Each `AuditEvent` stores `previous_hash` and `event_hash` (SHA-256). `GET /audit/verify-chain` walks the chain to detect tampering, deletions, or reordering. SOC 2 compliant.
18. **Prometheus metrics** — `GET /metrics` endpoint exposes `aiperture_permission_checks_total`, `aiperture_permission_check_duration_seconds`, cache hit/miss counters, auto-approve/deny counters, rate limit counters, risk budget exhaustion counters, and audit metrics.

## Architecture Rules

1. **Zero LLM calls.** Every decision is deterministic — glob matching, database queries, statistics.
2. **Append-only audit.** AuditEvents are never deleted or modified.
3. **SHA-256 everything.** Every artifact is hashed on storage. Integrity re-verifiable at any time.
4. **Fire-and-forget logging.** Audit/logging never breaks the primary operation.
5. **Provider agnostic.** The `runtime_id` field tracks which external runtime produced an artifact, but AIperture never calls any LLM.
6. **Differential privacy.** Cross-org intelligence uses RAPPOR-style local DP. True decisions never leave the org.

## Configuration

Config precedence (highest first):
1. Shell env vars (`export AIPERTURE_*=...`) — always win
2. `.aiperture.env` file values (written by `aiperture configure` or `PATCH /config`)
3. Defaults in Settings class

Run `aiperture configure` for an interactive setup wizard, or use `PATCH /config` at runtime.

### All settings (`AIPERTURE_*` env vars)

| Variable | Default | Tunable? | Description |
|---|---|---|---|
| `AIPERTURE_DB_BACKEND` | `sqlite` | No | `sqlite` or `postgres` |
| `AIPERTURE_DB_PATH` | `aiperture.db` | No | SQLite file path |
| `AIPERTURE_POSTGRES_URL` | `` | No | Postgres connection URL |
| `AIPERTURE_PERMISSION_LEARNING_ENABLED` | `true` | Yes | Auto-learn from human decisions |
| `AIPERTURE_PERMISSION_LEARNING_MIN_DECISIONS` | `10` | Yes | Min decisions before auto-deciding |
| `AIPERTURE_AUTO_APPROVE_THRESHOLD` | `0.95` | Yes | Approval rate to auto-approve |
| `AIPERTURE_AUTO_DENY_THRESHOLD` | `0.05` | Yes | Approval rate to auto-deny |
| `AIPERTURE_INTELLIGENCE_ENABLED` | `false` | Yes | Enable cross-org DP intelligence (opt-in) |
| `AIPERTURE_INTELLIGENCE_EPSILON` | `1.0` | Yes | DP noise level (higher = less private) |
| `AIPERTURE_INTELLIGENCE_MIN_ORGS` | `5` | Yes | Min orgs before surfacing global signal |
| `AIPERTURE_SENSITIVE_PATTERNS` | `*secret*,*credential*,...` | Yes | Comma-separated glob patterns for sensitive files (skip scope normalization) |
| `AIPERTURE_PATTERN_MAX_AGE_DAYS` | `90` | Yes | Days before auto-learned patterns expire without human reconfirmation |
| `AIPERTURE_RAPID_APPROVAL_WINDOW_SECONDS` | `60` | Yes | Time window for rubber-stamping detection |
| `AIPERTURE_RAPID_APPROVAL_MIN_COUNT` | `5` | Yes | Min approvals within window to flag as rubber-stamping |
| `AIPERTURE_RATE_LIMIT_PER_MINUTE` | `200` | Yes | Max permission checks per session per minute (0 = unlimited) |
| `AIPERTURE_SESSION_RISK_BUDGET` | `50.0` | Yes | Cumulative risk budget per session before escalating to ASK |
| `AIPERTURE_ARTIFACT_STORAGE_DIR` | `` | No | Artifact file storage directory |
| `AIPERTURE_API_KEY` | `` | No | Bearer token for HTTP API auth (empty = open access) |
| `AIPERTURE_API_HOST` | `0.0.0.0` | No | API server bind host |
| `AIPERTURE_API_PORT` | `8100` | No | API server port |

"Tunable" settings can be updated at runtime via `PATCH /config` or the CLI wizard (`aiperture configure`). Infrastructure settings (No) require restart.

## OpenClaw Integration

AIperture integrates with [OpenClaw (ClawDBot)](https://github.com/clawdbot/openclaw) as an MCP server. OpenClaw is an open-source AI agent that supports MCP tool servers.

### Quick Start (with OpenClaw)

```bash
# Prerequisites
npm install -g openclaw@latest      # install OpenClaw
pip install -e .                     # install AIperture

# Option A: Setup script
bash examples/openclaw_setup.sh
cd /tmp/aiperture-openclaw-demo && openclaw chat

# Option B: Python demo (auto-detects OpenClaw)
python examples/openclaw_demo.py

# Option C: Simulated mode (no OpenClaw needed)
python examples/openclaw_demo.py --sim
```

### How It Works

1. `examples/openclaw.json` wires AIperture as an MCP server with fast-learning thresholds (3 decisions, 80% threshold)
2. `examples/system_prompt.md` instructs the agent to call `check_permission` before every action
3. The agent asks to read a file -> AIperture denies (no history)
4. User approves 3 times -> AIperture learns the pattern
5. Agent asks to read another file -> AIperture auto-approves

### Config Files

| File | Purpose |
|------|---------|
| `examples/openclaw.json` | MCP server config (points AIperture at an isolated DB) |
| `examples/system_prompt.md` | Instructs the agent to gate all actions through AIperture |
| `examples/openclaw_setup.sh` | Creates `/tmp/aiperture-openclaw-demo/` with fresh DB |
