# AIperture

**The permission layer for AI agents.**

AI agents can run shell commands, read your files, call APIs, and modify databases. Today, you're the only thing standing between an agent and `rm -rf /`. Every action gets a yes/no popup. You either approve everything blindly or slow your workflow to a crawl.

AIperture sits between your agent runtime and the outside world. It learns your permission preferences over time and auto-approves the safe stuff — so you only get asked about things that actually matter.

**No LLM calls.** Every decision is deterministic. Zero latency from model inference, zero marginal cost per decision.

## Works with every major agent runtime

| Runtime | Integration | Status |
|---|---|---|
| **Claude Code** | Native hooks (PermissionRequest + PostToolUse) | Stable |
| **OpenAI Agents SDK** | Python middleware (`AipertureGuardrail`, `@aiperture_guard`) | Preview |
| **Google ADK** | Python middleware (`ADKPermissionGuard`) | Preview |
| **OpenClaw** | MCP server | Preview |
| **Cursor / Windsurf** | MCP server | Planned |
| **Any MCP runtime** | `aiperture mcp-serve` | Stable |
| **Any HTTP client** | REST API on `localhost:8100` | Stable |

```python
# OpenAI Agents SDK
from aiperture.integrations.openai import AipertureGuardrail
agent = Agent(name="my-agent", tools=[...], input_guardrails=[AipertureGuardrail()])

# Google ADK
from aiperture.integrations.google_adk import ADKPermissionGuard
guard = ADKPermissionGuard()

# Claude Code — one command, no code
# aiperture setup-claude --bootstrap=developer

# Any MCP runtime — point at the server
# aiperture mcp-serve
```

## How it works

```
Agent: "Can I run `npm test`?"
     │
     ▼
 AIperture
     │
     ├─ Day 1:   ASK   → You approved it. Recorded.
     ├─ Day 2:   ASK   → You approved it again. Recorded.
     ├─ ...
     ├─ Day 5:   ALLOW → Auto-approved. You learned this pattern.
     │
     ├─ "Can I run `rm -rf /`?"
     └─ Always:  ASK   → HIGH risk. Never auto-approved.
```

The learning engine is frequency counting with configurable thresholds — no ML, no embeddings, no training step. Scope normalization groups `git log`, `git log --oneline`, and `git log -5` into `git log*` so approvals accumulate faster.

## Getting started

```bash
pip install aiperture          # Python 3.12+
```

### Claude Code

```bash
aiperture setup-claude --bootstrap=developer
```

75 safe patterns pre-approved. Restart Claude Code and you're done. [Full guide →](docs/setup-claude-code.md)

### OpenAI Agents SDK

```python
from agents import Agent
from aiperture.integrations.openai import AipertureGuardrail

agent = Agent(
    name="my-agent",
    tools=[my_tool],
    input_guardrails=[AipertureGuardrail()],
)
```

Or wrap individual functions:

```python
from aiperture.integrations.openai import aiperture_guard

@aiperture_guard(session_id="my-session")
def read_file(path: str) -> str:
    return open(path).read()
```

### Google ADK

```python
from aiperture.integrations.google_adk import ADKPermissionGuard

guard = ADKPermissionGuard()
decision = guard.check("search_web", {"query": "AI safety"})
```

### OpenClaw / MCP runtimes

```bash
aiperture init-db
aiperture mcp-serve              # stdio transport
```

Point your runtime's MCP config at `aiperture mcp-serve`. [OpenClaw guide →](docs/setup-openclaw.md)

### REST API

```bash
aiperture serve                  # localhost:8100

curl -X POST localhost:8100/permissions/check \
  -H "Content-Type: application/json" \
  -d '{"tool": "shell", "action": "execute", "scope": "npm test"}'
```

## What you experience

**Day 1** — Run `aiperture bootstrap developer` and 75 common safe patterns are auto-approved from the start. You only get asked about things not in the preset.

**Day 3** — AIperture has learned your project-specific patterns. Custom build scripts, your test commands, project-specific file paths — all auto-approved.

**Day 7** — The only popups you see are for genuinely new or risky actions. Everything routine is handled. Everything dangerous is flagged. You have a full audit trail.

## Security

AIperture includes multiple layers of protection:

- **HMAC challenge-response** — cryptographic proof that a human saw the verdict before approving
- **Deep risk analysis** — unpacks `bash -c`, `curl | sh`, `python -c "os.system(...)"`, `find -exec`. HIGH/CRITICAL actions are never auto-approved
- **Fail-closed circuit breaker** — database failures default to ASK, never ALLOW
- **Rate limiting** — 200 checks/min per session (configurable), prevents DoS and enumeration
- **Session risk budgets** — cumulative risk scoring prevents "death by a thousand cuts" exfiltration
- **Rubber-stamping detection** — rapid approvals (5+ in 60s) are flagged and excluded from learning
- **Temporal decay** — learned patterns expire after 90 days without reconfirmation
- **Hash-chained audit trail** — SHA-256 chained, tamper-evident, SOC 2 compliant
- **Sensitive path protection** — secrets, credentials, keys skip scope normalization
- **API authentication** — optional bearer token auth on all HTTP endpoints

## Enterprise

AIperture is open-core. The open-source version includes the full permission engine, learning, risk scoring, audit trail, and all runtime integrations.

The enterprise version adds:

- Redis/Valkey session cache
- OIDC/SAML authentication
- Webhook audit forwarding (SIEM integration)
- Custom risk classification rules
- Postgres backend
- Multi-tenant isolation

The plugin architecture uses Python entry points — install `aiperture-enterprise` alongside `aiperture` and enterprise features activate automatically. [Plugin guide →](docs/plugins.md)

<details>
<summary><strong>Configuration reference</strong></summary>

All settings via `AIPERTURE_*` environment variables, or run `aiperture configure` for an interactive wizard.

| Variable | Default | Description |
|---|---|---|
| `AIPERTURE_PERMISSION_LEARNING_MIN_DECISIONS` | `10` | Min decisions before auto-deciding |
| `AIPERTURE_AUTO_APPROVE_THRESHOLD` | `0.95` | Approval rate to trigger auto-approve |
| `AIPERTURE_AUTO_DENY_THRESHOLD` | `0.05` | Approval rate to trigger auto-deny |
| `AIPERTURE_DEFAULT_DECISION` | `ask` | Fallback: `ask` or `deny` |
| `AIPERTURE_PATTERN_MAX_AGE_DAYS` | `90` | Days before patterns expire |
| `AIPERTURE_RATE_LIMIT_PER_MINUTE` | `200` | Max checks per session per minute |
| `AIPERTURE_SESSION_RISK_BUDGET` | `50.0` | Cumulative risk budget per session |
| `AIPERTURE_SENSITIVE_PATTERNS` | `*secret*,*credential*,...` | Glob patterns for sensitive files |
| `AIPERTURE_API_KEY` | — | Bearer token for HTTP API auth |
| `AIPERTURE_DB_BACKEND` | `sqlite` | `sqlite` or `postgres` |
| `AIPERTURE_LOG_LEVEL` | `DEBUG` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

</details>

<details>
<summary><strong>API endpoints</strong></summary>

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Database connectivity probe |
| `POST` | `/permissions/check` | Check if action is permitted |
| `POST` | `/permissions/record` | Record human decision |
| `POST` | `/permissions/grant` | Grant task-scoped permission |
| `GET` | `/permissions/patterns` | View learned patterns |
| `GET` | `/permissions/explain` | Human-readable explanation + risk |
| `POST` | `/artifacts/store` | SHA-256 verified artifact storage |
| `POST` | `/artifacts/{id}/verify` | Re-verify artifact integrity |
| `GET` | `/audit/events` | Query audit trail |
| `GET` | `/audit/verify-chain` | Verify hash chain integrity |
| `GET` | `/config` | Current settings |
| `PATCH` | `/config` | Update settings at runtime |
| `GET` | `/metrics` | Prometheus-compatible metrics |
| `POST` | `/hooks/permission-request` | Claude Code PermissionRequest hook |
| `POST` | `/hooks/post-tool-use` | Claude Code PostToolUse hook |

</details>

<details>
<summary><strong>Development</strong></summary>

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v       # 576 tests
```

16,000 lines of Python. ~1:1 source-to-test ratio. Requires Python 3.12+.

</details>

## License

Apache 2.0 — see [LICENSE](LICENSE).
