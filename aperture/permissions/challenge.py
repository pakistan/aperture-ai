"""HMAC challenge-response for human decision verification.

When check_permission returns DENY or ASK, the verdict includes a challenge
token (HMAC-SHA256 signed with a server-side secret). approve_action and
deny_action must present this token to record a decision.

The agent cannot forge the token because the secret is generated at server
startup and never exposed via MCP, REST, or logs.

Security properties:
- Tokens are bound to (tool, action, scope, organization_id, session_id)
- Tokens are single-use (consumed nonces are tracked and rejected)
- Server secret persists across restarts via APERTURE_HMAC_SECRET env var
"""

import hashlib
import hmac
import os
import threading
import time
from dataclasses import dataclass

# Server-side secret — read from env for persistence across restarts and
# multi-worker consistency. Falls back to random bytes for dev/single-worker.
_SERVER_SECRET: bytes = bytes.fromhex(os.environ["APERTURE_HMAC_SECRET"]) if os.environ.get("APERTURE_HMAC_SECRET") else os.urandom(32)

# Default max age: 1 hour
DEFAULT_MAX_AGE_SECONDS = 3600.0

# Single-use nonce tracking: set of consumed nonces with their expiry times
_consumed_nonces: dict[str, float] = {}
_nonce_lock = threading.Lock()

# Prune consumed nonces older than this (matches max token age)
_NONCE_PRUNE_INTERVAL = DEFAULT_MAX_AGE_SECONDS


@dataclass
class ChallengeToken:
    """An HMAC challenge bound to a specific permission check."""

    token: str  # hex-encoded HMAC
    nonce: str  # unique per-check
    issued_at: float  # time.time()
    tool: str
    action: str
    scope: str


def create_challenge(
    tool: str,
    action: str,
    scope: str,
    organization_id: str = "",
    session_id: str = "",
) -> ChallengeToken:
    """Create an HMAC challenge for a permission check.

    The challenge is bound to (tool, action, scope, organization_id, session_id)
    so it cannot be replayed across orgs or sessions.
    """
    nonce = os.urandom(16).hex()
    issued_at = time.time()
    message = f"{tool}|{action}|{scope}|{organization_id}|{session_id}|{nonce}|{issued_at}".encode()
    token = hmac.new(_SERVER_SECRET, message, hashlib.sha256).hexdigest()
    return ChallengeToken(
        token=token,
        nonce=nonce,
        issued_at=issued_at,
        tool=tool,
        action=action,
        scope=scope,
    )


def verify_challenge(
    token: str,
    nonce: str,
    issued_at: float,
    tool: str,
    action: str,
    scope: str,
    *,
    organization_id: str = "",
    session_id: str = "",
    max_age_seconds: float = DEFAULT_MAX_AGE_SECONDS,
) -> bool:
    """Verify an HMAC challenge token.

    Returns True if the token is valid, not expired, and not already consumed.
    Each token can only be used once (single-use nonce tracking).
    """
    if not token or not nonce:
        return False

    # Check expiry
    now = time.time()
    if now - issued_at > max_age_seconds:
        return False

    # Check if nonce was already consumed (replay protection)
    with _nonce_lock:
        if nonce in _consumed_nonces:
            return False

    # Recompute HMAC (includes org and session binding)
    message = f"{tool}|{action}|{scope}|{organization_id}|{session_id}|{nonce}|{issued_at}".encode()
    expected = hmac.new(_SERVER_SECRET, message, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(token, expected):
        return False

    # Mark nonce as consumed (single-use)
    with _nonce_lock:
        # Double-check after acquiring lock
        if nonce in _consumed_nonces:
            return False
        _consumed_nonces[nonce] = now
        _prune_expired_nonces(now)

    return True


def _prune_expired_nonces(now: float) -> None:
    """Remove consumed nonces older than the max token age. Called under _nonce_lock."""
    cutoff = now - _NONCE_PRUNE_INTERVAL
    expired = [n for n, t in _consumed_nonces.items() if t < cutoff]
    for n in expired:
        del _consumed_nonces[n]


def reset_secret_for_testing() -> None:
    """Reset the server secret and consumed nonces. ONLY for use in tests."""
    global _SERVER_SECRET
    _SERVER_SECRET = os.urandom(32)
    with _nonce_lock:
        _consumed_nonces.clear()
