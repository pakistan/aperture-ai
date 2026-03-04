"""Prometheus metrics for AIperture observability.

Lightweight counters and histograms for permission engine monitoring.
Uses the prometheus_client library (no external dependencies).
"""

import time
from contextlib import contextmanager

from prometheus_client import Counter, Gauge, Histogram

# Permission check metrics
PERMISSION_CHECKS = Counter(
    "aiperture_permission_checks_total",
    "Total permission checks",
    ["decision", "decided_by"],
)

PERMISSION_CHECK_DURATION = Histogram(
    "aiperture_permission_check_duration_seconds",
    "Permission check latency",
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
)

# Cache metrics
SESSION_CACHE_HITS = Counter(
    "aiperture_session_cache_hits_total",
    "Session cache hits",
)

SESSION_CACHE_MISSES = Counter(
    "aiperture_session_cache_misses_total",
    "Session cache misses",
)

# Learning metrics
AUTO_APPROVED = Counter(
    "aiperture_auto_approved_total",
    "Actions auto-approved by learned patterns",
)

AUTO_DENIED = Counter(
    "aiperture_auto_denied_total",
    "Actions auto-denied by learned patterns",
)

RATE_LIMITED = Counter(
    "aiperture_rate_limited_total",
    "Permission checks denied by rate limiting",
)

RISK_BUDGET_EXHAUSTED = Counter(
    "aiperture_risk_budget_exhausted_total",
    "Actions escalated due to risk budget exhaustion",
)

# Audit metrics
AUDIT_EVENTS = Counter(
    "aiperture_audit_events_total",
    "Total audit events recorded",
)

AUDIT_WRITE_FAILURES = Counter(
    "aiperture_audit_write_failures_total",
    "Failed audit event writes",
)

# Learned patterns gauge
LEARNED_PATTERNS = Gauge(
    "aiperture_learned_patterns_total",
    "Number of learned permission patterns",
)


# Hook metrics
HOOK_PERMISSION_REQUESTS = Counter(
    "aiperture_hook_permission_requests_total",
    "Hook permission requests processed",
    ["decision"],
)

HOOK_POST_TOOL_USE = Counter(
    "aiperture_hook_post_tool_use_total",
    "Hook post-tool-use events recorded",
)

HOOK_INFERRED_DENIALS = Counter(
    "aiperture_hook_inferred_denials_total",
    "Denials inferred from timed-out pending requests",
)


@contextmanager
def track_check_duration():
    """Context manager to track permission check duration."""
    start = time.perf_counter()
    yield
    PERMISSION_CHECK_DURATION.observe(time.perf_counter() - start)
