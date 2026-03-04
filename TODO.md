# Aperture — Architecture Review TODO

Generated from deep codebase analysis + competitive research (March 2026).
Organized by priority. Each task includes full context so it can be executed independently.

---

## IMMEDIATE — Critical Fixes (ALL COMPLETE)

### 1. ~~Add HTTP API Authentication~~ DONE

**Status**: Completed (March 2026). Added `AIPERTURE_API_KEY` env var, `aiperture/api/auth.py`, global FastAPI dependency. 14 tests in `tests/test_auth.py`.

~~**Priority**: Critical~~
**Files**: `aiperture/api/routes/*.py`, `aiperture/config.py`, `main.py`
**Effort**: Small

**Problem**: The REST API at `localhost:8100` has zero authentication. No API keys, no bearer tokens, nothing. Anyone on the network can call `POST /permissions/record`, `PATCH /config`, or any other endpoint.

**What to do**:
- Add a `AIPERTURE_API_KEY` setting to `config.py` (optional, no auth when unset for local dev)
- Create a FastAPI dependency that checks the `Authorization: Bearer <key>` header
- Apply the dependency to all routes
- When `AIPERTURE_API_KEY` is set, reject requests without a valid key with HTTP 401
- The MCP server (`mcp_server.py`) is unaffected — it uses stdio transport which is inherently process-local

**Why it matters**: Without this, any process on the network can forge permission decisions, change config thresholds, or read the audit trail.

---

### 2. ~~Fix Learning Engine Hardcoded Thresholds~~ DONE

**Status**: Completed (March 2026). Learning engine now reads thresholds from config settings.

~~**Priority**: Critical~~
**Files**: `aiperture/permissions/learning.py` (lines 244-282)
**Effort**: Small

**Problem**: `learning.py` hardcodes thresholds even though `config.py` defines tunable settings:
- Auto-approve threshold: hardcoded `0.95` in learning.py vs `AIPERTURE_AUTO_APPROVE_THRESHOLD` in config
- Auto-deny threshold: hardcoded `0.05` vs `AIPERTURE_AUTO_DENY_THRESHOLD`
- Min decisions: hardcoded `10` vs `AIPERTURE_PERMISSION_LEARNING_MIN_DECISIONS`

The engine (`engine.py` line 576) correctly reads config, but `PermissionLearner.get_recommendation()` does not.

**What to do**:
- Inject `Settings` (or the relevant threshold values) into `PermissionLearner.__init__()`
- Replace hardcoded `0.95`, `0.05`, and `10` in `get_recommendation()` with config values
- Update tests to verify config values are respected

**Why it matters**: Users tuning thresholds via `aiperture configure` or `PATCH /config` think they're changing behavior, but the learning engine ignores their settings.

---

### 3. ~~Add Recursion Depth Limit to Risk Analysis~~ DONE

**Status**: Completed (March 2026). Added `_depth` kwarg with `_MAX_RECURSION_DEPTH=5`. 10 tests in `tests/test_risk_deep.py::TestRecursionDepthLimit`.

~~**Priority**: Critical (DoS vector)~~
**Files**: `aiperture/permissions/risk.py` (lines 461-472)
**Effort**: Tiny

**Problem**: `classify_risk()` recursively scores shell wrappers. A crafted input like `bash -c "bash -c 'bash -c \"bash -c ...\"'"` has no depth limit and could cause stack exhaustion.

The recursive call is at line ~467:
```python
inner_result = classify_risk(tool, action, inner_cmd)
```

**What to do**:
- Add a `_depth` parameter to `classify_risk()` (default 0)
- Increment on each recursive call
- If `_depth > 5`, return HIGH risk with factor `"max_recursion_depth_exceeded"`
- The public API signature stays the same (callers don't pass `_depth`)

**Why it matters**: An attacker could craft a deeply nested shell wrapper to DoS the permission engine.

---

### 4. ~~Add Composite Database Index~~ DONE

**Status**: Completed (March 2026). Added `ix_permlog_org_tool_action` composite index on `PermissionLog(organization_id, tool, action)`.

~~**Priority**: Critical (performance)~~
**Files**: `aiperture/models/permission.py`
**Effort**: Tiny

**Problem**: The most critical query path is `_check_learned()` in `engine.py` (lines 523-590):
```sql
SELECT * FROM permission_logs
WHERE organization_id = ? AND tool = ? AND action = ?
  AND decided_by LIKE 'human:%' AND revoked_at IS NULL
ORDER BY created_at DESC
```

Individual column indexes exist on `organization_id`, `task_id`, etc., but there's no composite index on the query's actual filter pattern. At 100K+ rows, this query degrades significantly.

**What to do**:
- Add a composite index to `PermissionLog`:
  ```python
  __table_args__ = (
      Index("ix_permlog_org_tool_action", "organization_id", "tool", "action"),
  )
  ```
- For PostgreSQL deployments, also document a partial index:
  ```sql
  CREATE INDEX ix_permlog_learned ON permission_logs(organization_id, tool, action)
  WHERE revoked_at IS NULL;
  ```

**Why it matters**: Every permission check hits this query. Without the index, performance degrades linearly with decision history size.

---

### 5. ~~Add Circuit Breaker for Database Failures~~ DONE

**Status**: Completed (March 2026). `_check_learned()` and `_check_task_permissions()` fail closed on DB error. Added `GET /health` with DB probe. 10 tests in `tests/test_circuit_breaker.py`.

~~**Priority**: Critical~~
**Files**: `aiperture/permissions/engine.py` (lines 523-590, 492-520)
**Effort**: Small

**Problem**: `_log()` (line 592) catches exceptions silently (fire-and-forget for audit — correct). But `_check_learned()` and `_check_task_permissions()` do NOT catch database exceptions. If the database is unavailable:
- Permission checks throw unhandled exceptions
- The behavior (fail open vs fail closed) is undefined

**What to do**:
- Wrap `_check_learned()` and `_check_task_permissions()` in try/except
- On database failure, **fail closed** (return no match, falling through to default deny)
- Log a WARNING with the exception details
- Add a health check endpoint (`GET /health`) that verifies database connectivity
- Consider adding a configurable `AIPERTURE_FAIL_MODE` setting (`closed` | `open`, default `closed`)

**Why it matters**: Database failures during permission checks should result in deny (safe), not crashes (unpredictable).

---

## HIGH PRIORITY — Security Hardening (ALL COMPLETE)

### 6. ~~Add Rate Limiting~~ DONE

**Status**: Completed (March 2026). Per-session rate limiter in `PermissionEngine.check()` with in-memory counter and 1-minute sliding window. Configurable via `AIPERTURE_RATE_LIMIT_PER_MINUTE` (default 200). Returns DENY verdict with `rate_limit_exceeded` factor. 5 tests in `tests/test_rate_limiting.py`.

~~**Priority**: High~~
**Files**: `aiperture/permissions/engine.py`, `aiperture/config.py`
**Effort**: Medium

---

### 7. ~~Add Cumulative Session Risk Scoring~~ DONE

**Status**: Completed (March 2026). `_session_risk_budget` dict tracks cumulative risk per session. Risk score mapping: LOW=0.1, MEDIUM=0.3, HIGH=0.7, CRITICAL=1.0. Configurable via `AIPERTURE_SESSION_RISK_BUDGET` (default 50.0). Exhausted budget escalates ALLOW → ASK. 6 tests in `tests/test_session_risk.py`.

~~**Priority**: High~~
**Files**: `aiperture/permissions/engine.py`, `aiperture/config.py`
**Effort**: Medium

---

### 8. ~~Add Sensitive Paths List (Skip Normalization)~~ DONE

**Status**: Completed (March 2026). `_is_sensitive()` in `scope_normalize.py` checks filename and full path against configurable glob patterns. Sensitive files skip normalization, requiring exact-match learning. Configurable via `AIPERTURE_SENSITIVE_PATTERNS`. 16 tests in `tests/test_sensitive_paths.py`.

~~**Priority**: High~~
**Files**: `aiperture/permissions/scope_normalize.py`, `aiperture/config.py`
**Effort**: Small

---

### 9. ~~Add Hash Chaining to Audit Trail~~ DONE

**Status**: Completed (March 2026). `previous_hash` and `event_hash` fields on `AuditEvent`. SHA-256 hash chain computed on each insert. `GET /audit/verify-chain` endpoint walks the chain and detects tampering, deletions, or reordering. 8 tests in `tests/test_hash_chain.py`.

~~**Priority**: High~~
**Files**: `aiperture/models/audit.py`, `aiperture/stores/audit_store.py`, `aiperture/api/routes/audit.py`
**Effort**: Medium

---

### 10. ~~Add Temporal Pattern Decay~~ DONE

**Status**: Completed (March 2026). `_check_learned()` checks most recent human decision age against `AIPERTURE_PATTERN_MAX_AGE_DAYS` (default 90). Expired patterns fall through to ASK, forcing periodic re-confirmation. 5 tests in `tests/test_temporal_decay.py`.

~~**Priority**: High~~
**Files**: `aiperture/permissions/engine.py`, `aiperture/config.py`
**Effort**: Small

---

### 11. ~~Add Rubber-Stamping Detection~~ DONE

**Status**: Completed (March 2026). `record_human_decision()` tracks approval timestamps per `(session_id, tool, action)`. Rapid approvals (5+ within 60s) flagged with `:rapid` suffix on `decided_by`. Rapid decisions excluded from learning. Configurable via `AIPERTURE_RAPID_APPROVAL_WINDOW_SECONDS` and `AIPERTURE_RAPID_APPROVAL_MIN_COUNT`. 5 tests in `tests/test_rubber_stamping.py`.

~~**Priority**: High~~
**Files**: `aiperture/permissions/engine.py`, `aiperture/config.py`
**Effort**: Small

---

### 12. ~~Persist HMAC Nonces to Database~~ DONE

**Status**: Completed (March 2026). `ConsumedNonce` SQLModel table in `models/permission.py`. `verify_challenge()` checks in-memory cache first, then DB. Persists after verification. `cleanup_expired_nonces()` for maintenance. 5 tests in `tests/test_nonce_persistence.py`.

~~**Priority**: High~~
**Files**: `aiperture/permissions/challenge.py`, `aiperture/models/permission.py`
**Effort**: Small

---

### 13. ~~Add Prometheus Metrics~~ DONE

**Status**: Completed (March 2026). `aiperture/metrics.py` defines Prometheus counters, histograms, and gauges. `GET /metrics` endpoint serves Prometheus text format. `PermissionEngine.check()` instrumented with timing and decision counters. 6 tests in `tests/test_metrics.py`. Health check (`GET /health`) was already implemented in item 5.

~~**Priority**: High~~
**Files**: `aiperture/metrics.py`, `aiperture/api/routes/metrics.py`, `aiperture/api/app.py`, `aiperture/permissions/engine.py`
**Effort**: Medium

---

## MEDIUM PRIORITY — Functionality Improvements

### 14. Make Exponential Decay Half-Life Configurable

**Priority**: Medium
**Files**: `aiperture/permissions/learning.py` (line 48), `aiperture/config.py`
**Effort**: Tiny

**Problem**: The decay half-life is hardcoded at 30 days in `PermissionLearner.__init__()`. A 90-day-old decision has only 12.5% weight. For some orgs, stable long-running policies should count more.

**What to do**:
- Add `AIPERTURE_DECAY_HALF_LIFE_DAYS` to `config.py` (default 30, tunable)
- Pass it to `PermissionLearner.__init__()`
- Document: shorter half-life = faster adaptation to policy changes, longer = more stable patterns

---

### 15. Add Sequence Numbers to Audit Events

**Priority**: Medium
**Files**: `aiperture/models/audit.py`, `aiperture/stores/audit_store.py`
**Effort**: Tiny

**Problem**: Audit events use `created_at` timestamps for ordering. If two events occur in the same millisecond, ordering is ambiguous. This matters for the compliance report which compares permission checks against executions.

**What to do**:
- Add `sequence: int` field to `AuditEvent` (auto-incrementing)
- Use it as the primary ordering key (with `created_at` as secondary)
- SQLite and Postgres both support auto-increment

---

### 16. Document Single-Worker Requirement

**Priority**: Medium
**Files**: `CLAUDE.md`, `README.md`, `aiperture/permissions/engine.py`
**Effort**: Tiny

**Problem**: The session cache (`_session_cache`) and nonce tracking (`_consumed_nonces`) are in-memory per-process. Multi-worker Uvicorn deployments will have inconsistent session caches and partial nonce protection.

**What to do**:
- Add a "Deployment" section to README documenting:
  - Single-worker mode: `uvicorn main:app --workers 1` (recommended for most deployments)
  - Multi-worker mode requires: `AIPERTURE_HMAC_SECRET` env var (shared secret), sticky sessions or Redis cache (not yet implemented)
- Add a log WARNING on startup if `--workers > 1` is detected without `AIPERTURE_HMAC_SECRET`

---

### 17. Add HMAC Secret Rotation

**Priority**: Medium
**Files**: `aiperture/permissions/challenge.py`
**Effort**: Small

**Problem**: The server HMAC secret lives for the lifetime of the process with no rotation mechanism. If compromised, all challenge tokens are forgeable until process restart.

**What to do**:
- Support `AIPERTURE_HMAC_SECRET` as a comma-separated list of hex secrets (first = current, rest = previous)
- On token generation: always use the first (current) secret
- On token verification: try each secret in order (current first, then previous)
- Document rotation procedure: add new secret to front of list, deploy, remove old secret after 1 hour (token max age)
- Add `AIPERTURE_HMAC_SECRET_ROTATION_ENABLED` config flag

---

### 18. Fix Org Count Estimation in Intelligence

**Priority**: Medium
**Files**: `aiperture/permissions/intelligence.py` (line 83)
**Effort**: Small

**Problem**: Global stats estimate org count as `sqrt(noisy_total)` — a crude heuristic since no `org_id` is stored globally (by design for privacy). Two orgs contributing 25 decisions each would be estimated as ~7 orgs, making the `min_orgs` threshold unreliable.

**What to do**:
- Option A (simple): Raise `INTELLIGENCE_MIN_ORGS` default from 5 to 20 where the estimate is more stable
- Option B (better): Use a HyperLogLog sketch with DP noise for approximate distinct count
  - Store an HLL sketch per (tool, action, scope_pattern) in `GlobalPermissionStat`
  - Each org contributes a hashed, noisy org identifier
  - HLL provides ~2% error at 1.5KB memory per counter
- Option C (simplest): Add a `reporting_orgs` counter that increments once per unique `(org_hash, tool, action)` tuple, where `org_hash = HMAC(org_id, global_salt)` — reveals count but not identity

---

### 19. Improve Audit Event State Tracking

**Priority**: Medium
**Files**: `aiperture/stores/audit_store.py`, `aiperture/mcp_server.py`, `aiperture/permissions/engine.py`
**Effort**: Small

**Problem**: `AuditEvent` has `previous_state` and `new_state` JSON fields, but most call sites don't populate them. State-changing events (config updates, revocations, task permission grants) should always include before/after state for reconstructive auditing.

**What to do**:
- In `engine.revoke_pattern()`: populate `previous_state` with the matching decisions and `new_state` with `{"revoked_at": timestamp}`
- In `config.py update_settings()`: populate `previous_state` with old values and `new_state` with new values
- In `engine.grant_task_permission()`: populate `new_state` with the grant details
- In `engine.record_human_decision()`: populate `new_state` with the decision and verdict context

---

### 20. Add Scope Escalation Detection

**Priority**: Medium
**Files**: `aiperture/permissions/engine.py`
**Effort**: Medium

**Problem**: If an agent has been approved for `filesystem.read` on `src/*.py`, nothing flags it as suspicious when it suddenly requests `filesystem.read` on `/etc/passwd`. The request will be denied (no learned pattern), but the attempt is not flagged as anomalous.

**What to do**:
- Track approved scopes per session in `_session_cache` (already tracked for decisions)
- When a new check comes in, compare the requested scope against previously approved scopes
- If the new scope is in a completely different path hierarchy or domain, add an `"escalation_attempt"` factor to the verdict
- Log an audit event with `event_type = "scope_escalation_detected"`
- This is informational, not blocking — the existing cascade handles the actual decision

---

## STRATEGIC — Long-Term Architecture

### 21. Redis-Backed Session Cache for Multi-Worker

**Priority**: Strategic
**Files**: `aiperture/permissions/engine.py` (lines 48-52, 88-100)
**Effort**: Medium-Large

**Problem**: The session cache is an in-memory `OrderedDict` with `threading.Lock()`. It works perfectly for single-worker deployments but doesn't share across multiple Uvicorn workers or multiple server instances.

**What to do**:
- Create a `SessionCache` interface/protocol:
  ```python
  class SessionCache(Protocol):
      def get(self, key: tuple) -> PermissionDecision | None: ...
      def set(self, key: tuple, decision: PermissionDecision) -> None: ...
      def clear_pattern(self, org_id: str, tool: str, action: str, scope: str) -> None: ...
  ```
- Implement `InMemorySessionCache` (current behavior) and `RedisSessionCache`
- Add `AIPERTURE_SESSION_CACHE_BACKEND` config (`memory` | `redis`, default `memory`)
- Add `AIPERTURE_REDIS_URL` config
- Redis keys: `aiperture:session:{org_id}:{session_id}:{tool}:{action}:{scope}:{content_hash}`
- Redis TTL: match session lifetime or 1 hour default

---

### 22. Optional External Policy Engine Backend

**Priority**: Strategic
**Files**: `aiperture/permissions/engine.py` (static rule matching, lines 462-489)
**Effort**: Large

**Problem**: Aperture's static rule layer uses simple glob matching. Enterprises with existing OPA/Cedar/OpenFGA deployments want to use their existing policy infrastructure for the static rules while getting Aperture's learning/risk/audit on top.

**What to do**:
- Create a `PolicyBackend` protocol:
  ```python
  class PolicyBackend(Protocol):
      def evaluate(self, tool: str, action: str, scope: str, context: dict) -> PermissionDecision | None: ...
  ```
- Implement `BuiltinPolicyBackend` (current fnmatch behavior)
- Add optional `OpaPolicyBackend` (calls OPA via HTTP), `CedarPolicyBackend` (evaluates Cedar policies via Rust bindings)
- Add `AIPERTURE_POLICY_BACKEND` config (`builtin` | `opa` | `cedar`, default `builtin`)
- The cascade becomes: session → task → learned → **external policy** → default deny
- Static rules in the built-in format remain as a fallback

---

### 23. Build OpenAI Agents SDK Integration

**Priority**: Strategic
**Files**: New file `examples/openai_agents_demo.py`, new package `aiperture/integrations/openai_agents.py`
**Effort**: Medium

**Problem**: Aperture currently integrates only via MCP (Claude Code, OpenClaw) and HTTP API. The OpenAI Agents SDK has a guardrails system that Aperture could plug into, expanding the addressable market significantly.

**What to do**:
- Create an `ApertureGuardrail` class that implements the OpenAI Agents SDK guardrail interface
- Before each tool execution, call `check_permission()` via the HTTP API
- If the verdict is DENY or ASK, raise the guardrail failure
- If ASK, present the challenge to the user and record the decision
- Create an example similar to `examples/openclaw_demo.py` showing:
  1. Define an OpenAI agent with filesystem and shell tools
  2. Attach `ApertureGuardrail` to the agent
  3. Demonstrate the learning loop

---

### 24. Proxy Mode (Intercept Tool Calls at Transport Layer)

**Priority**: Strategic
**Files**: New module `aiperture/proxy.py`
**Effort**: Large

**Problem**: Currently, Aperture is advisory — the agent must voluntarily call `check_permission` via MCP. Anthropic's sleeper agents research shows that safety-trained models can skip safety checks under certain conditions. The compliance tracking (`report_tool_execution` / `get_compliance_report`) detects violations after the fact, but doesn't prevent them.

**What to do**:
- Create an MCP proxy that sits between the agent runtime and the actual tool servers
- The proxy intercepts every tool call, runs it through Aperture's permission engine, and only forwards allowed calls
- Architecture: `Agent → Aperture MCP Proxy → Actual MCP Servers`
- The proxy re-exposes all tools from downstream servers but wraps each with a permission check
- For non-ALLOW decisions, return the HMAC challenge as the tool result
- This eliminates the compliance gap entirely — the agent cannot bypass permission checks because they're at the transport layer

**Why it's strategic**: This transforms Aperture from an advisory system to an enforcement system. It's the difference between a firewall rule and a "please don't go to that website" policy.

---

### 25. Plan Approval Mode

**Priority**: Strategic
**Files**: `aiperture/permissions/engine.py`, `aiperture/api/routes/permissions.py`, `aiperture/mcp_server.py`
**Effort**: Medium

**Problem**: GitHub Copilot Workspace approves entire execution plans, not individual actions. Aperture currently checks one action at a time. For complex tasks with 20+ tool calls, per-call approval is exhausting even with learning.

**What to do**:
- Add `POST /permissions/check-plan` endpoint that accepts a list of `(tool, action, scope)` tuples
- Return a composite verdict: all-allowed, all-denied, or mixed (with per-action breakdowns)
- Compute aggregate risk: sum of individual risk scores, plus a "plan complexity" factor
- For mixed verdicts, return the plan with each action annotated (auto-approved, needs review, denied)
- The human reviews and approves the entire plan with a single HMAC challenge
- Add `check_plan` MCP tool

---

### 26. Web Dashboard for Enterprise Security Teams

**Priority**: Strategic
**Files**: New directory `aiperture/dashboard/`
**Effort**: Large

**Problem**: Enterprise security teams want visual dashboards, not just APIs and CLI. No CISO will adopt a tool they can't see.

**What to do**:
- Build a lightweight web UI (could be a single-page app served by FastAPI)
- Key views:
  - **Decision feed**: Real-time stream of permission checks with risk color coding
  - **Learned patterns**: Table of auto-approved/denied patterns with approval rates and age
  - **Risk heatmap**: Tool × action matrix colored by risk tier
  - **Session inspector**: Drill into a session's permission history
  - **Compliance report**: Visual comparison of executions vs. permission checks
  - **Config editor**: UI for tunable settings (replaces `aiperture configure` CLI)
- Auth: Protect with the API key from task #1, or add SSO (task #27)

---

### 27. SSO/OIDC Integration

**Priority**: Strategic
**Files**: `aiperture/config.py`, `aiperture/api/` (new middleware)
**Effort**: Medium-Large

**Problem**: Enterprise deployments need to map `decided_by` fields to real corporate identities. Currently, the human identity is whatever string the MCP client passes (e.g., `"human:user1"`). There's no verification that "user1" is who they claim to be.

**What to do**:
- Add `AIPERTURE_OIDC_ISSUER`, `AIPERTURE_OIDC_CLIENT_ID`, `AIPERTURE_OIDC_AUDIENCE` config settings
- When configured, require JWT bearer tokens on the HTTP API
- Extract user identity from the JWT claims (e.g., `sub`, `email`)
- For MCP: pass the authenticated identity via the `organization_id` or a new `user_id` parameter
- Map `decided_by` to verified identities: `"human:alice@company.com"` from JWT, not self-reported

---

### 28. SIEM Integration

**Priority**: Strategic
**Files**: `aiperture/stores/audit_store.py`, `aiperture/config.py`
**Effort**: Medium

**Problem**: Enterprises need audit events to flow into their existing SIEM (Splunk, Datadog, Elastic, etc.) for centralized monitoring and alerting.

**What to do**:
- Add a log forwarding mechanism in `audit_store.py`:
  - Option A: Write audit events as structured JSON to a configurable log file (SIEM agents pick it up)
  - Option B: Forward events via HTTP webhook to a configurable URL
  - Option C: Support syslog (CEF or OCSF format) for direct SIEM ingestion
- Add `AIPERTURE_AUDIT_FORWARD_URL` config (webhook endpoint)
- Add `AIPERTURE_AUDIT_LOG_FILE` config (structured JSON log path)
- Fire-and-forget: forwarding failures should not block the primary operation

---

### 29. Anomaly Detection

**Priority**: Strategic
**Files**: `aiperture/permissions/engine.py`, new file `aiperture/permissions/anomaly.py`
**Effort**: Medium

**Problem**: No mechanism to detect when an agent's behavior deviates from its historical norm. An agent that normally reads Python files suddenly executing shell commands is suspicious regardless of whether each individual action is approved.

**What to do**:
- Track per-session statistics: `{tool: count}` distribution
- Compare current session's distribution to the org's historical norm
- Use a simple chi-squared or KL-divergence measure
- If deviation exceeds a threshold, add `"anomalous_session"` factor to subsequent verdicts
- Log an audit event with `event_type = "anomaly_detected"`
- Add `AIPERTURE_ANOMALY_DETECTION_ENABLED` config (default false, opt-in)

---

### 30. Add Conditions Field to Permission Model (ABAC Support)

**Priority**: Strategic
**Files**: `aiperture/models/permission.py`, `aiperture/permissions/engine.py` (lines 462-489)
**Effort**: Medium

**Problem**: Static rules are flat `Permission(tool, action, scope, decision)` tuples. Enterprises need attribute-based conditions: "allow filesystem.write on src/** IF the agent's runtime is 'claude-code' AND the org's environment is 'development'."

**What to do**:
- Add `conditions: dict | None` field to `Permission` model
- Conditions are simple key-value matches:
  ```json
  {"runtime_id": "claude-code", "environment": "development"}
  ```
- In `_match_static()`, after glob matching, check if all condition keys match the check context
- Pass context as a new parameter to `check()`: `context: dict | None = None`
- MCP tool `check_permission` gains an optional `context` parameter
- This keeps the zero-dependency philosophy while enabling ABAC for enterprises

---

## REFERENCE — Research Findings Summary

### Competitive Landscape
- **Guardrails AI**: Output validation, not authorization. Complementary, not competitive.
- **NeMo Guardrails**: Conversation flow control using LLM calls. Different layer.
- **Lakera/Prompt Security**: Prompt injection detection (WAF for LLMs). Different layer.
- **OPA/Cedar**: General-purpose policy engines. No learning, no risk scoring, no agent-specific features.
- **Zanzibar/SpiceDB**: ReBAC at scale. No learning, no risk scoring.
- **Permit.io/Auth0 FGA/AWS VP**: Traditional app auth platforms. No agent-specific features.

**Aperture's moat**: Learning + Risk Classification + HMAC Challenge + DP Intelligence. No competitor has any of these in combination.

### Standards Alignment
- **OWASP LLM Top 10**: Strong coverage of LLM07 (Insecure Plugin Design) and LLM08 (Excessive Agency)
- **NIST AI RMF**: Good alignment across Govern/Map/Measure/Manage functions
- **SOC 2**: Audit trail satisfies CC6.1, CC7.2, CC8.1 (needs hash chaining for integrity)
- **HIPAA**: Covers access controls, audit controls, integrity controls, authentication

### Architecture Grades
| Dimension | Grade |
|---|---|
| Core architecture | A |
| Security model | A- |
| OWASP alignment | A |
| Learning engine | B+ (needs hardening) |
| Differential privacy | B+ (org count estimation) |
| Code quality | A- |
| Scalability | B (pagination, indexes) |
| Enterprise readiness | B- (needs auth, SSO, dashboard) |
| Market positioning | A |
