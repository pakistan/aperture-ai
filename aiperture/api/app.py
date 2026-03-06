"""FastAPI application factory."""

import json
import logging
import logging.handlers
import re
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from aiperture import plugins
from aiperture.api.auth import require_api_key
from aiperture.api.routes import artifacts, audit, config, health, hooks, intelligence, metrics, permissions
from aiperture.db import init_db

logger = logging.getLogger("aiperture.requests")

# ANSI color codes
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_BLUE = "\033[34m"
_MAGENTA = "\033[35m"
_CYAN = "\033[36m"
_WHITE = "\033[37m"
_BG_RED = "\033[41m"
_BG_GREEN = "\033[42m"
_BG_YELLOW = "\033[43m"
_BG_BLUE = "\033[44m"

# Disable colors if not a TTY
if not sys.stderr.isatty():
    _RESET = _BOLD = _DIM = ""
    _RED = _GREEN = _YELLOW = _BLUE = _MAGENTA = _CYAN = _WHITE = ""
    _BG_RED = _BG_GREEN = _BG_YELLOW = _BG_BLUE = ""


def _status_color(status: int) -> str:
    if status < 300:
        return _GREEN
    if status < 400:
        return _YELLOW
    if status < 500:
        return _RED
    return f"{_BOLD}{_RED}"


def _decision_color(decision: str) -> str:
    d = decision.lower()
    if d == "allow":
        return f"{_BG_GREEN}{_WHITE}{_BOLD} ALLOW {_RESET}"
    if d == "deny":
        return f"{_BG_RED}{_WHITE}{_BOLD} DENY {_RESET}"
    if d == "ask":
        return f"{_BG_YELLOW}{_WHITE}{_BOLD} ASK {_RESET}"
    return decision


def _route_label(path: str) -> str:
    """Short colored label for the route category."""
    if "/permissions" in path:
        return f"{_MAGENTA}PERM{_RESET}"
    if "/hooks" in path:
        return f"{_CYAN}HOOK{_RESET}"
    if "/artifacts" in path:
        return f"{_BLUE}ARTIFACT{_RESET}"
    if "/audit" in path:
        return f"{_YELLOW}AUDIT{_RESET}"
    if "/health" in path:
        return f"{_GREEN}HEALTH{_RESET}"
    if "/config" in path:
        return f"{_WHITE}CONFIG{_RESET}"
    if "/intelligence" in path:
        return f"{_MAGENTA}INTEL{_RESET}"
    if "/metrics" in path:
        return f"{_DIM}METRICS{_RESET}"
    return f"{_DIM}OTHER{_RESET}"


def _format_req_summary(path: str, body: dict | str) -> str:
    """Extract the most useful info from the request for a one-line summary."""
    if not isinstance(body, dict):
        return ""
    parts = []
    # Permission check / hook — show tool, action, scope
    tool = body.get("tool", "")
    action = body.get("action", "")
    scope = body.get("scope", "")
    if tool:
        parts.append(f"{_BOLD}{tool}{_RESET}:{action}")
    if scope:
        scope_display = scope if len(scope) <= 80 else scope[:77] + "..."
        parts.append(f"{_DIM}{scope_display}{_RESET}")
    # Hook-specific fields
    if "tool_name" in body:
        parts.append(f"{_BOLD}{body['tool_name']}{_RESET}")
    if "tool_input" in body:
        inp = body["tool_input"]
        if isinstance(inp, dict):
            # Show command for Bash, file_path for Read, etc.
            for key in ("command", "file_path", "pattern", "query"):
                if key in inp:
                    val = str(inp[key])
                    val_display = val if len(val) <= 80 else val[:77] + "..."
                    parts.append(f"{_DIM}{val_display}{_RESET}")
                    break
    return " ".join(parts)


def _format_resp_summary(path: str, body: dict | str) -> str:
    """Extract the most useful info from the response for a one-line summary."""
    if not isinstance(body, dict):
        return ""
    parts = []
    # Permission verdict
    decision = body.get("decision", "")
    if decision:
        parts.append(_decision_color(decision))
        decided_by = body.get("decided_by", "")
        if decided_by:
            parts.append(f"{_DIM}by {decided_by}{_RESET}")
    # Risk tier
    risk = body.get("risk", {})
    if isinstance(risk, dict) and risk.get("tier"):
        tier = risk["tier"]
        tier_colors = {"low": _GREEN, "medium": _YELLOW, "high": _RED, "critical": f"{_BOLD}{_RED}"}
        color = tier_colors.get(tier, "")
        parts.append(f"risk:{color}{tier}{_RESET}")
    # Hook response
    if "allow" in body and not decision:
        if body["allow"]:
            parts.append(f"{_BG_GREEN}{_WHITE}{_BOLD} ALLOW {_RESET}")
        else:
            parts.append(f"{_BG_RED}{_WHITE}{_BOLD} DENY {_RESET}")
    # PostToolUse hook — show recorded status
    if "recorded" in body:
        if body["recorded"]:
            parts.append(f"{_GREEN}recorded{_RESET}")
        else:
            reason = body.get("reason", "skipped")
            parts.append(f"{_DIM}skipped ({reason}){_RESET}")
    # Health
    status = body.get("status", "")
    if status == "healthy":
        parts.append(f"{_GREEN}healthy{_RESET}")
    elif status == "degraded":
        parts.append(f"{_RED}degraded{_RESET}")
    return " ".join(parts)


class RequestResponseLoggingMiddleware(BaseHTTPMiddleware):
    """Log request bodies and response bodies with colors."""

    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()
        method = request.method
        path = request.url.path

        # Read request body
        body_bytes = await request.body()
        req_body: dict | str = ""
        if body_bytes:
            try:
                req_body = json.loads(body_bytes)
            except (json.JSONDecodeError, UnicodeDecodeError):
                req_body = body_bytes.decode("utf-8", errors="replace")

        # Process request
        response = await call_next(request)

        # Read response body
        resp_chunks = []
        async for chunk in response.body_iterator:
            if isinstance(chunk, str):
                resp_chunks.append(chunk.encode("utf-8"))
            else:
                resp_chunks.append(chunk)
        resp_bytes = b"".join(resp_chunks)

        response = Response(
            content=resp_bytes,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.media_type,
        )

        resp_body: dict | str = ""
        if resp_bytes:
            try:
                resp_body = json.loads(resp_bytes)
            except (json.JSONDecodeError, UnicodeDecodeError):
                resp_body = resp_bytes.decode("utf-8", errors="replace")

        elapsed_ms = (time.perf_counter() - start) * 1000

        # Build colored output
        sc = _status_color(response.status_code)
        label = _route_label(path)
        header = (
            f"{_DIM}{'─' * 60}{_RESET}\n"
            f"{label} {_BOLD}{method} {path}{_RESET} "
            f"{sc}{response.status_code}{_RESET} "
            f"{_DIM}{elapsed_ms:.0f}ms{_RESET}"
        )

        req_summary = _format_req_summary(path, req_body)
        resp_summary = _format_resp_summary(path, resp_body)

        lines = [header]
        if req_summary:
            lines.append(f"  {_CYAN}>{_RESET} {req_summary}")
        if resp_summary:
            lines.append(f"  {_GREEN}<{_RESET} {resp_summary}")

        logger.info("\n".join(lines))

        return response


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    plugins.load_all()
    init_db()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="AIperture",
        description="The permission layer for AI agents. Controls what passes through.",
        version="0.19.1",
        lifespan=lifespan,
        dependencies=[Depends(require_api_key)],
    )

    # Suppress uvicorn access logs — our middleware already logs everything better
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

    # Verbose request/response logging with colors
    req_logger = logging.getLogger("aiperture.requests")
    req_logger.setLevel(logging.DEBUG)
    if not req_logger.handlers:
        # Console handler (with ANSI colors)
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(logging.Formatter("%(message)s"))
        req_logger.addHandler(console_handler)

        # File handler (strip ANSI colors, reuse root logger's file handler)
        for h in logging.getLogger().handlers:
            if isinstance(h, logging.handlers.RotatingFileHandler):

                class _StripAnsiFormatter(logging.Formatter):
                    _ansi_re = re.compile(r"\033\[[0-9;]*m")

                    def format(self, record):
                        msg = super().format(record)
                        return self._ansi_re.sub("", msg)

                file_handler = logging.handlers.RotatingFileHandler(
                    h.baseFilename,
                    maxBytes=h.maxBytes,
                    backupCount=h.backupCount,
                )
                file_handler.setLevel(h.level)
                file_handler.setFormatter(_StripAnsiFormatter("%(asctime)s [aiperture.requests] %(levelname)s %(message)s"))
                req_logger.addHandler(file_handler)
                break
    app.add_middleware(RequestResponseLoggingMiddleware)

    app.include_router(permissions.router, prefix="/permissions", tags=["permissions"])
    app.include_router(artifacts.router, prefix="/artifacts", tags=["artifacts"])
    app.include_router(audit.router, prefix="/audit", tags=["audit"])
    app.include_router(intelligence.router, prefix="/intelligence", tags=["intelligence"])
    app.include_router(config.router, prefix="/config", tags=["config"])
    app.include_router(hooks.router, prefix="/hooks", tags=["hooks"])
    app.include_router(health.router, tags=["health"])
    app.include_router(metrics.router, tags=["metrics"])

    # Register plugin routers if any
    plugin_router = plugins.get("router")
    if plugin_router is not None:
        for router_info in plugin_router.get_routers():
            app.include_router(router_info)

    return app
