"""Thread-safe in-memory tracker for pending permission requests.

When AIperture has no opinion on a PermissionRequest (returns {}),
the request is tracked as "pending". If PostToolUse arrives, the user
approved it. If it times out (5 min), we infer denial.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


_DEFAULT_TIMEOUT_SECONDS = 300  # 5 minutes


@dataclass
class PendingRequest:
    """A permission request awaiting resolution."""

    tool: str
    action: str
    scope: str
    session_id: str
    organization_id: str
    created_at: float = field(default_factory=time.time)


class PendingTracker:
    """Track pending permission requests for denial inference."""

    def __init__(self, timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS):
        self._pending: dict[str, PendingRequest] = {}
        self._lock = threading.Lock()
        self._timeout = timeout_seconds

    def add(self, tool_use_id: str, request: PendingRequest) -> None:
        """Track a pending permission request."""
        with self._lock:
            self._pending[tool_use_id] = request

    def resolve(self, tool_use_id: str) -> PendingRequest | None:
        """Resolve a pending request (user approved). Returns the request or None."""
        with self._lock:
            return self._pending.pop(tool_use_id, None)

    def collect_expired(self) -> list[PendingRequest]:
        """Collect and remove timed-out requests (inferred denials)."""
        now = time.time()
        expired: list[PendingRequest] = []
        with self._lock:
            to_remove = []
            for tid, req in self._pending.items():
                if now - req.created_at > self._timeout:
                    expired.append(req)
                    to_remove.append(tid)
            for tid in to_remove:
                del self._pending[tid]
        return expired

    def __len__(self) -> int:
        with self._lock:
            return len(self._pending)
