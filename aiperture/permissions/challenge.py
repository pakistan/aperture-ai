"""HMAC challenge-response for human decision verification.

When check_permission returns DENY or ASK, the verdict includes a challenge
token (HMAC-SHA256 signed with a server-side secret). approve_action and
deny_action must present this token to record a decision.

The agent cannot forge the token because the secret is generated at server
startup and never exposed via MCP, REST, or logs.

Security properties:
- Tokens are bound to (tool, action, scope, organization_id, session_id)
- Tokens are single-use (consumed nonces are tracked and rejected)
- Server secret persists across restarts via AIPERTURE_HMAC_SECRET env var

IMPORTANT — forgery vs relay:
    HMAC prevents an agent from *forging* a challenge token. However, it does
    NOT prevent an agent from *relaying* a valid token. When the agent has
    direct access to both check_permission (which returns a valid token) and
    approve_action (which consumes it), the agent can call check → approve in
    sequence and self-approve without any human involvement.

    This is why approve_action/deny_action are NOT exposed as MCP tools.
    In the MCP path (where the agent is the caller), the hook-based
    integration is safe because Claude Code's native permission dialog is
    the human gate. In the HTTP API path, the assumption is that a
    human-controlled UI sits between check and approve.
"""

import hashlib
import hmac
import os
import threading
import time
from dataclasses import dataclass

# Server-side secret — read from env for persistence across restarts and
# multi-worker consistency. Falls back to random bytes for dev/single-worker.
_SERVER_SECRET: bytes = bytes.fromhex(os.environ["AIPERTURE_HMAC_SECRET"]) if os.environ.get("AIPERTURE_HMAC_SECRET") else os.urandom(32)

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
    # First check in-memory cache, then fall back to database
    with _nonce_lock:
        if nonce in _consumed_nonces:
            return False
    if _check_nonce_in_db(nonce):
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

    # Persist to database for replay protection across restarts
    _persist_nonce(nonce)

    return True


def _prune_expired_nonces(now: float) -> None:
    """Remove consumed nonces older than the max token age. Called under _nonce_lock."""
    cutoff = now - _NONCE_PRUNE_INTERVAL
    expired = [n for n, t in _consumed_nonces.items() if t < cutoff]
    for n in expired:
        del _consumed_nonces[n]


def _check_nonce_in_db(nonce: str) -> bool:
    """Check if a nonce exists in the database. Returns True if consumed."""
    try:
        from sqlmodel import Session, select

        from aiperture.db import get_engine
        from aiperture.models.permission import ConsumedNonce

        with Session(get_engine()) as session:
            result = session.get(ConsumedNonce, nonce)
            if result is not None:
                # Add to in-memory cache so we don't hit DB again
                with _nonce_lock:
                    _consumed_nonces[nonce] = time.time()
                return True
    except Exception:
        pass  # DB unavailable — rely on in-memory cache only
    return False


def _persist_nonce(nonce: str) -> None:
    """Persist a consumed nonce to database. Fire-and-forget."""
    try:
        from sqlmodel import Session

        from aiperture.db import get_engine
        from aiperture.models.permission import ConsumedNonce

        with Session(get_engine()) as session:
            session.add(ConsumedNonce(nonce=nonce))
            session.commit()
    except Exception:
        pass  # Fire-and-forget — in-memory cache is the primary guard


def cleanup_expired_nonces() -> int:
    """Remove expired nonces from both in-memory cache and database.

    Returns the number of nonces cleaned from the database.
    """
    now = time.time()
    cutoff = now - DEFAULT_MAX_AGE_SECONDS

    # Clean in-memory
    with _nonce_lock:
        _prune_expired_nonces(now)

    # Clean database
    db_count = 0
    try:
        from datetime import UTC, datetime

        from sqlmodel import Session, select

        from aiperture.db import get_engine
        from aiperture.models.permission import ConsumedNonce

        cutoff_dt = datetime.fromtimestamp(cutoff, tz=UTC).replace(tzinfo=None)
        with Session(get_engine()) as session:
            expired = session.exec(
                select(ConsumedNonce).where(ConsumedNonce.consumed_at < cutoff_dt)
            ).all()
            for n in expired:
                session.delete(n)
                db_count += 1
            session.commit()
    except Exception:
        pass
    return db_count


def reset_secret_for_testing() -> None:
    """Reset the server secret and consumed nonces. ONLY for use in tests."""
    global _SERVER_SECRET
    _SERVER_SECRET = os.urandom(32)
    with _nonce_lock:
        _consumed_nonces.clear()
