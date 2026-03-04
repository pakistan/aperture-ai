# AIperture

**The permission layer for AI agents.**

AI agents can run shell commands, read your files, call APIs, and modify databases. Today, you're the only thing standing between an agent and `rm -rf /`. Every action gets a yes/no popup. You either approve everything blindly or slow your workflow to a crawl.

AIperture fixes this. It sits between your agent runtime and the outside world, learns your permission preferences over time, and auto-approves the safe stuff — so you only get asked about things that actually matter.

> **Setup guides:** [Claude Code](docs/setup-claude-code.md) | [OpenClaw](docs/setup-openclaw.md) | [REST API](#rest-api) | [Python library](#python-library)

## How it works

```
┌──────────────────────────────────────────────────────────────────┐
│                      Your Agent Runtime                          │
│           (Claude Code, OpenAI Agents, LangChain, etc.)          │
└──────────────────────┬───────────────────────────────────────────┘
                       │
                       │  "Can this agent run `npm test`?"
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│                         AIPERTURE                                 │
│                                                                  │
│   ┌─────────────┐  ┌──────────────┐  ┌───────────────────────┐   │
│   │ Permission  │  │ Risk Scoring │  │ Learning Engine       │   │
│   │ Engine      │  │              │  │                       │   │
│   │             │  │ tool danger  │  │ You approved npm test │   │
│   │ RBAC rule   │─▶│ × action     │  │ 15 times in a row.    │   │
│   │ Task grants │  │   severity   │  │ Auto-approving now.   │   │
│   │ Learned     │  │ × scope      │  │                       │   │
│   │   patterns  │  │   breadth    │  │ You denied rm -rf /   │   │
│   │             │  │              │  │ every time.           │   │
│   └──────┬───┬──┘  └──────────────┘  │  Auto-denying now.    │   │
│          │   │                       └-──────────────────────┘   │
│          │   │     ┌──────────────┐  ┌───────────────────────┐   │
│          │   │     │ Audit Trail  │  │ Artifact Store        │   │ 
│          │   └────▶│ Every        │  │ SHA-256 verified      │   │
│          │         │ decision     │  │ immutable storage     │   │
│          │         │ logged       │  │ for agent outputs     │   │
│          │         └──────────────┘  └───────────────────────┘   │
└──────────┼───────────────────────────────────────────────────────┘
           │
           ▼
     ┌─────────────┐
     │  ALLOW      │  ← auto-approved (learned pattern)
     │  DENY       │  ← auto-denied (learned pattern)
     │  ASK        │  ← no pattern yet, ask the human
     └─────────────┘
```

**No LLM calls.** Every decision is deterministic — glob matching, frequency counting, and pattern lookup. AIperture never phones home, never calls an API, and adds zero latency from model inference.

**Runtime agnostic.** AIperture integrates via MCP (for Claude Code, OpenClaw), REST API (for any HTTP-capable runtime), or as a Python library (direct import). MCP is one integration path, not a dependency.

## What you experience

**Day 1** — Run `aiperture bootstrap developer` and 75 common safe patterns are auto-approved from the start. You only get asked about things not in the preset. Every decision you make is recorded.

**Day 3** — AIperture has learned your project-specific patterns on top of the bootstrap. Custom build scripts, your test commands, project-specific file paths — all auto-approved. You still get prompted for `rm`, `curl`, and anything touching production.

**Day 7** — The only popups you see are for genuinely new or risky actions. Everything routine is auto-approved. Everything dangerous is auto-denied. Your agent moves faster and you have a full audit trail of every decision.

## Getting started

### 1. Install

```bash
pip install aiperture
```

Requires Python 3.12+. This installs the `aiperture` CLI and the Python package.

Verify it worked:

```bash
aiperture --help
```

You should see:

```
AIperture — The permission layer for AI agents

Commands:
  setup-claude  Set up AIperture as Claude Code's MCP permission layer
  mcp-serve    Run as MCP server (stdio transport)
  serve        Run HTTP API server
  init-db      Initialize the database
  configure    Interactive setup wizard
  bootstrap    Seed permission decisions from a preset
  revoke       Revoke auto-approval for a permission pattern
```

### 2. Connect your agent runtime

Pick whichever runtime you use:

#### Claude Code (one command)

```bash
aiperture setup-claude --bootstrap=developer
```

That's it. This creates `.mcp.json` in your project, initializes the database, and pre-seeds 75 safe patterns. Restart Claude Code and AIperture is active with 14 tools.

Options:
- `--global` — install to `~/.claude/.mcp.json` (all projects instead of just this one)
- `--bootstrap=developer` — pre-seed 75 safe patterns (git, file reads, test runners, linters)
- `--bootstrap=readonly` — 48 patterns (reads only)
- No `--bootstrap` — clean slate, learn everything from scratch

**[Full Claude Code guide →](docs/setup-claude-code.md)** — includes learning loop diagram, tuning, and troubleshooting.

#### Other MCP runtimes (manual setup)

If you're not using Claude Code, initialize the database and bootstrap manually:

```bash
aiperture init-db
aiperture bootstrap developer    # optional: 75 pre-approved safe patterns
```

Other presets: `readonly` (48 patterns — reads only) or `minimal` (clean slate).

#### OpenClaw

```bash
npm install -g openclaw@latest
```

Create `openclaw.json` in your project root:

```json
{
  "mcpServers": {
    "aiperture": {
      "command": "aiperture",
      "args": ["mcp-serve"],
      "env": {
        "AIPERTURE_DB_PATH": "./aiperture.db"
      }
    }
  }
}
```

Add a [system prompt](examples/system_prompt.md) that tells the agent to call `check_permission` before every action, then run `openclaw chat`.

**[Full OpenClaw guide →](docs/setup-openclaw.md)** — includes step-by-step walkthrough, demo mode, and production settings.

#### REST API

Start the server and point any agent runtime at it:

```bash
aiperture serve    # Runs on localhost:8100
```

```bash
# Check a permission
curl -X POST localhost:8100/permissions/check \
  -H "Content-Type: application/json" \
  -d '{"tool": "shell", "action": "execute", "scope": "npm test"}'

# Record a human decision (feeds the learning engine)
curl -X POST localhost:8100/permissions/record \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "shell", "action": "execute", "scope": "npm test",
    "decision": "allow", "decided_by": "user-1"
  }'

# Check database health
curl localhost:8100/health
```

If you set `AIPERTURE_API_KEY`, add the auth header to all requests:

```bash
curl -X POST localhost:8100/permissions/check \
  -H "Authorization: Bearer your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"tool": "shell", "action": "execute", "scope": "npm test"}'
```

#### Python library

```python
from aiperture.permissions import PermissionEngine
from aiperture.models import PermissionDecision

engine = PermissionEngine()

# Check if an action is allowed
verdict = engine.check("shell", "execute", "npm test", rules=[])

# Record a human decision
engine.record_human_decision(
    tool="shell", action="execute", scope="npm test",
    decision=PermissionDecision.ALLOW, decided_by="user-1",
    organization_id="my-org",
)

# After enough decisions, the engine auto-approves
verdict = engine.check("shell", "execute", "npm test", rules=[])
print(verdict.decision)  # PermissionDecision.ALLOW
```

### 5. What to expect

Once connected, here's what your first week looks like:

**First session (with bootstrap)** — Common safe actions are auto-approved immediately. You'll only be prompted for actions outside the preset — writes, installs, network calls, etc. Approve the safe ones; AIperture records your decisions.

**First session (without bootstrap)** — Every action gets checked. You'll approve the safe ones (reading files, running tests, git commands). This is normal — AIperture is building its model of your preferences.

**After ~10 approvals per action** — AIperture starts auto-approving the patterns you've consistently allowed. `git status`? Auto-approved. `npm test`? Auto-approved. You stop seeing prompts for routine actions.

**Dangerous actions stay flagged** — `rm -rf`, `DROP TABLE`, shell commands touching production paths — these are scored as HIGH/CRITICAL risk and always require your explicit approval, no matter how many times you've approved other things.

**You can check what it learned at any time:**

```bash
# Via the API
curl localhost:8100/permissions/patterns?min_decisions=5

# Or ask your agent
"Show me what AIperture has learned"
```

**Optional: tune the learning speed**

The defaults (10 decisions, 95% approval rate) are conservative. To make Aperture learn faster, run the interactive wizard:

```bash
aiperture configure
```

Or set environment variables directly:

```bash
export AIPERTURE_PERMISSION_LEARNING_MIN_DECISIONS=5
export AIPERTURE_AUTO_APPROVE_THRESHOLD=0.90
```

## How learning works

There's no ML here. No model, no embeddings, no training step. The learning engine is frequency counting with configurable thresholds:

1. Every human decision is recorded as a row: `(tool, action, scope, decision, timestamp, decided_by)`
2. When a new permission check comes in, the engine queries all prior human decisions for that `(tool, action, scope)` tuple
3. It computes the **approval rate** = `allow_count / total_decisions`
4. If `approval_rate >= 0.95` and `total_decisions >= 10` → **auto-approve**
5. If `approval_rate <= 0.05` and `total_decisions >= 10` → **auto-deny**
6. Otherwise → **ask the human again**

Both thresholds are configurable (`AIPERTURE_AUTO_APPROVE_THRESHOLD`, `AIPERTURE_PERMISSION_LEARNING_MIN_DECISIONS`).

Two things make this smarter than a flat lookup table:

- **Scope normalization** — `git log --oneline -5` is normalized to `git log*`, so approving any `git log` variant counts toward the same pattern. File paths are normalized similarly: `src/components/Button.tsx` → `src/components/*.tsx`. This means approvals accumulate faster.
- **Exponential decay** — Recent decisions are weighted more heavily (30-day half-life). If you approved something 6 months ago but started denying it last week, the recent denials dominate.

**Safety rails:** Actions scored as HIGH or CRITICAL risk (e.g., `rm -rf`, `DROP TABLE`, `curl | sh`) are **never** auto-approved regardless of history. They always require explicit human approval.

## Why not just use CLAUDE.md rules?

If you use Claude Code, you can already write `CLAUDE.md` rules or use `/permissions` to allowlist specific commands. That works. AIperture is for when it stops working:

| | CLAUDE.md / `/permissions` | Aperture |
|---|---|---|
| **Setup** | You write and maintain rules manually | Learns from your decisions automatically |
| **Scope** | One agent runtime (Claude Code) | Any runtime — Claude Code, OpenAI Agents, LangChain, OpenClaw, custom |
| **Granularity** | Command-level allowlists | Normalizes variants (`git log*`), tracks by content hash, scores risk |
| **Audit** | No record of what was approved or when | Append-only log of every decision with timestamps and who decided |
| **Team use** | Per-developer, not shared | Org-level crowd signals — surfaces what your team usually approves |
| **Revocation** | Delete the rule | `aiperture revoke` soft-deletes with audit trail, forces fresh decisions |
| **Verification** | Trust that the agent respects the rules | HMAC challenge-response proves a human saw the verdict |
| **Risk analysis** | None — a rule is a rule | Deep shell analysis (unwraps `bash -c`, pipe-to-exec, `find -exec`) |

If you're a solo developer running Claude Code on personal projects, `CLAUDE.md` rules are probably fine. AIperture is built for teams, for multi-runtime setups, and for anyone who needs an audit trail.

## Features

| Feature | What it does |
|---------|-------------|
| **Permission Engine** | RBAC rules + task-scoped grants (ReBAC) + auto-learning from human decisions |
| **API Authentication** | Optional bearer token auth (`AIPERTURE_API_KEY`) — protects all HTTP endpoints when set |
| **Risk Scoring** | OWASP-inspired `tool danger × action severity × scope breadth` with deep analysis of shell wrappers, pipe-to-exec, and scripting oneliners (recursion-depth capped) |
| **Learning Engine** | Frequency-based pattern detection: tracks approval/denial rates per (tool, action, scope) and auto-decides after 10+ consistent decisions |
| **Crowd Wisdom** | Aggregates decisions across your org — surfaces what your team usually approves or denies |
| **Artifact Store** | SHA-256 verified, immutable storage for every agent output |
| **Audit Trail** | Append-only, hash-chained compliance log of every permission decision — tamper-evident with `GET /audit/verify-chain` |
| **Compliance Tracking** | Detects unchecked tool executions — tools that ran without a prior permission check |
| **HMAC Challenge-Response** | Cryptographic proof that a human saw the verdict before approving — prevents agent self-approval |
| **Bootstrap Presets** | Pre-seed safe patterns (`developer`, `readonly`, `minimal`) so AIperture is useful from the first session |
| **Revocation** | Undo learned patterns instantly — `aiperture revoke shell execute "rm*"` |
| **Content Awareness** | Differentiates writes to the same file by content hash — a rewrite of `main.py` is flagged even if a prior write was approved |
| **Scope Normalization** | Groups `git log`, `git log --oneline`, `git log -5` into `git log*` so approvals accumulate faster |
| **Sensitive Path Protection** | Configurable glob patterns (`AIPERTURE_SENSITIVE_PATTERNS`) skip scope normalization — sensitive files require exact-match learning |
| **Rate Limiting** | Per-session rate limiter (200 checks/min default) prevents DoS and permission enumeration |
| **Session Risk Scoring** | Cumulative risk budget per session — many individually-safe actions that compound are escalated to ASK |
| **Temporal Pattern Decay** | Auto-learned patterns expire after 90 days (configurable) without human reconfirmation |
| **Rubber-Stamping Detection** | Rapid approvals (5+ within 60s) are flagged and excluded from the learning engine |
| **Hash-Chained Audit** | SHA-256 hash chain on audit events — `GET /audit/verify-chain` detects tampering or deletion |
| **Nonce Persistence** | HMAC nonces persisted to database — closes replay attack window across server restarts |
| **Prometheus Metrics** | `GET /metrics` — permission check counters, latency histograms, cache hit rates, risk budget counters |
| **Health Check** | `GET /health` — database connectivity probe, returns healthy/degraded status |
| **Circuit Breaker** | Database failures during permission checks fail closed (default deny), never crash or allow |
| **REST API** | FastAPI server — works with any agent runtime over HTTP |
| **MCP Server** | 14 tools for Claude Code and other MCP-compatible runtimes |
| **CLI** | `aiperture setup-claude`, `aiperture remove-claude`, `aiperture serve`, `aiperture init-db`, `aiperture configure`, `aiperture bootstrap`, `aiperture revoke` |

## How decisions are made

Aperture resolves permissions in this order, stopping at the first match:

```
1. Session memory     →  Already decided this session? Reuse it.
2. Task grants (ReBAC) →  Scoped permission for this specific task?
3. Learned patterns   →  10+ consistent human decisions? Auto-decide.
4. Static RBAC rules  →  Glob-matched rules (most specific wins).
5. Default deny       →  No match? Deny.
```

When enrichment is enabled, each verdict also includes:
- **Risk assessment** — tier (LOW/MEDIUM/HIGH/CRITICAL), score, factors, reversibility
- **Human-readable explanation** — what the action does, in plain English
- **Crowd signal** — what your org has historically decided for this pattern
- **Similar patterns** — related decisions that might inform this one
- **Recommendation** — auto-approve, auto-deny, suggest a rule, or keep asking

## Security hardening

Aperture includes several layers of protection against agent misuse:

### HTTP API authentication

Set `AIPERTURE_API_KEY` to require a bearer token on all HTTP API requests:

```bash
export AIPERTURE_API_KEY="your-secret-key-here"
aiperture serve
```

All requests must include `Authorization: Bearer your-secret-key-here`. Requests without a valid key get HTTP 401. When unset (the default), all requests pass — suitable for local development.

The MCP server (stdio transport) is unaffected — it runs as a child process and doesn't use HTTP.

### HMAC challenge-response (anti self-approval)

Every `check_permission` verdict includes a cryptographic challenge token (HMAC-signed with a server-side secret). To approve or deny an action, the caller must echo back the challenge, nonce, and timestamp from the original verdict. This proves a human saw the verdict before acting on it. Agents cannot forge these tokens because they don't have the server secret.

### Deep risk analysis

The risk scorer doesn't just look at the top-level command. It unpacks shell wrappers (`bash -c "rm -rf /"` scores as `rm -rf /`, not `bash`), detects pipe-to-exec patterns (`curl | sh`), scripting oneliners (`python -c "os.system(...)"`), and dangerous `find -exec`/`-delete` commands. Recursion depth is capped at 5 levels to prevent DoS from deeply nested wrappers. HIGH and CRITICAL risk actions are **never** auto-approved regardless of history.

### Fail-closed circuit breaker

If the database becomes unavailable during a permission check, the engine **fails closed** — it defaults to deny rather than crashing or allowing. This ensures database outages never result in unauthorized actions.

Check database health anytime:

```bash
curl localhost:8100/health
# {"status": "healthy", "database": "connected", "service": "aiperture"}
```

### Compliance audit tracking

Two tools detect when agents bypass permission checks:

- `report_tool_execution` — called after an agent runs a tool, creating an execution record
- `get_compliance_report` — compares executions against prior permission checks, revealing compliance gaps (tools that ran without ever being checked)

### Bootstrap presets

Skip the approval fatigue of the first session:

```bash
aiperture bootstrap developer    # 75 safe patterns (git, file reads, test runners, linters)
aiperture bootstrap readonly     # 48 patterns (reads only)
aiperture bootstrap minimal      # Clean slate
```

### Revocation

Undo any learned pattern instantly:

```bash
aiperture revoke shell execute "rm*"              # Revoke all rm-related auto-approvals
aiperture revoke filesystem write "*.py" --org=prod  # Org-scoped revocation
```

Revoked decisions are soft-deleted (preserved for audit) but excluded from learning, crowd signals, and auto-approval. The pattern immediately requires fresh human decisions.

### Rate limiting

Per-session rate limiter prevents runaway or compromised agents from flooding the permission engine:

```bash
export AIPERTURE_RATE_LIMIT_PER_MINUTE=200    # default; 0 = unlimited
```

When exceeded, permission checks return DENY with `rate_limit_exceeded` factor. Prevents DoS and permission enumeration attacks.

### Cumulative session risk scoring

AIperture tracks a cumulative risk budget per session. Each action's risk score (LOW=0.1, MEDIUM=0.3, HIGH=0.7, CRITICAL=1.0) is deducted from the budget. When the budget is exhausted, all subsequent checks are escalated to ASK — even if the pattern would normally be auto-approved.

```bash
export AIPERTURE_SESSION_RISK_BUDGET=50.0     # default
```

This prevents "death by a thousand cuts" attacks where many individually-safe actions compound into data exfiltration.

### Sensitive path protection

Scope normalization groups files like `src/config.py` and `src/secrets.py` into `src/*.py` for faster learning. But this creates a privilege escalation vector for sensitive files. AIperture skips normalization for files matching configurable glob patterns:

```bash
export AIPERTURE_SENSITIVE_PATTERNS="*secret*,*credential*,*password*,*.env,*.pem,*.key,*token*,.env*,*id_rsa*,*private*"
```

Sensitive files require exact-match learning — 10 approvals of `src/secrets.py` specifically, not `src/*.py`.

### Temporal pattern decay

Auto-learned patterns expire after a configurable period without human reconfirmation:

```bash
export AIPERTURE_PATTERN_MAX_AGE_DAYS=90      # default
```

If the most recent human decision for a pattern is older than the configured age, auto-approval is disabled and the action falls through to ASK. This implements temporal least privilege — permissions decay back to requiring approval.

### Rubber-stamping detection

If a fatigued human rapidly approves many actions (5+ within 60 seconds for the same pattern), those decisions are flagged with a `:rapid` suffix and excluded from the learning engine. This prevents approval fatigue from compromising learning quality.

```bash
export AIPERTURE_RAPID_APPROVAL_WINDOW_SECONDS=60
export AIPERTURE_RAPID_APPROVAL_MIN_COUNT=5
```

### Hash-chained audit trail

Every audit event is cryptographically chained using SHA-256. Each event stores `previous_hash` and `event_hash`. Any deletion, reordering, or tampering breaks the chain and is detectable:

```bash
curl localhost:8100/audit/verify-chain
# {"valid": true, "events_checked": 142, "chain_status": "intact"}
```

This creates a tamper-evident audit log suitable for SOC 2 compliance.

### HMAC nonce persistence

HMAC challenge nonces are persisted to the database (with in-memory caching for performance). This closes the replay attack window that existed when nonces were only tracked in-memory — a server restart no longer allows token replay within the 1-hour expiry window.

### Prometheus metrics

Production observability via Prometheus-compatible metrics:

```bash
curl localhost:8100/metrics
```

Exposes: `aiperture_permission_checks_total`, `aiperture_permission_check_duration_seconds`, cache hit/miss counters, auto-approve/deny counters, rate limit counters, risk budget exhaustion counters, and audit write metrics.

### Content awareness

Pass a `content_hash` (SHA-256 of the content being written) with your permission check. Different content gets separate cache entries, so rewriting `main.py` with new content is flagged even if a prior write to `main.py` was approved. The verdict includes a `content_changed` flag when the same file is being written with different content than before.

### Scope normalization

The learning engine normalizes command scopes so that `git log`, `git log --oneline`, and `git log --oneline -5` all count toward the same `git log*` pattern. This means approvals accumulate faster and the system learns from fewer interactions.

<details>
<summary><strong>Configuration</strong></summary>

All settings via environment variables (prefix `AIPERTURE_`):

| Variable | Default | Description |
|---|---|---|
| `AIPERTURE_DB_BACKEND` | `sqlite` | `sqlite` or `postgres` |
| `AIPERTURE_DB_PATH` | `aiperture.db` | SQLite file path |
| `AIPERTURE_POSTGRES_URL` | — | Postgres connection URL |
| `AIPERTURE_PERMISSION_LEARNING_ENABLED` | `true` | Auto-learn from human decisions |
| `AIPERTURE_PERMISSION_LEARNING_MIN_DECISIONS` | `10` | Min decisions before auto-deciding |
| `AIPERTURE_AUTO_APPROVE_THRESHOLD` | `0.95` | Approval rate to trigger auto-approve |
| `AIPERTURE_AUTO_DENY_THRESHOLD` | `0.05` | Approval rate to trigger auto-deny |
| `AIPERTURE_INTELLIGENCE_ENABLED` | `false` | Cross-org intelligence (opt-in) |
| `AIPERTURE_SENSITIVE_PATTERNS` | `*secret*,*credential*,...` | Glob patterns for sensitive files (skip normalization) |
| `AIPERTURE_PATTERN_MAX_AGE_DAYS` | `90` | Days before auto-learned patterns expire |
| `AIPERTURE_RAPID_APPROVAL_WINDOW_SECONDS` | `60` | Time window for rubber-stamping detection |
| `AIPERTURE_RAPID_APPROVAL_MIN_COUNT` | `5` | Min approvals in window to flag as rubber-stamping |
| `AIPERTURE_RATE_LIMIT_PER_MINUTE` | `200` | Max permission checks per session per minute |
| `AIPERTURE_SESSION_RISK_BUDGET` | `50.0` | Cumulative risk budget per session |
| `AIPERTURE_LOG_LEVEL` | `DEBUG` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `AIPERTURE_LOG_FILE` | — | File path for log output (e.g. `~/.aiperture/aiperture.log`). 5 MB rotating, 3 backups |
| `AIPERTURE_API_KEY` | — | Bearer token for HTTP API auth (empty = open access) |
| `AIPERTURE_API_HOST` | `0.0.0.0` | API bind host |
| `AIPERTURE_API_PORT` | `8100` | API bind port |

Or run `aiperture configure` for an interactive setup wizard.

</details>

<details>
<summary><strong>Development</strong></summary>

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
```

Requires Python 3.12+.

</details>

## License

Apache 2.0 — see [LICENSE](LICENSE).
