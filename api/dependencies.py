"""FastAPI dependency injection."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Annotated, Any

import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from agentguard.analyzer.backends import create_backend
from agentguard.analyzer.intent_analyzer import IntentAnalyzer
from agentguard.auth.jwt_utils import auth_enabled, check_token_revocation, verify_token
from agentguard.auth.rate_limiter import get_rate_limiter
from agentguard.core.errors import AgentGuardHTTPError, ErrorCode
from agentguard.interceptor.interceptor import Interceptor
from agentguard.ledger.db import PostgresEventLedger
from agentguard.ledger.event_ledger import EventLedger
from agentguard.policy.engine import PolicyEngine

_bearer = HTTPBearer(auto_error=False)


async def verify_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict[str, Any]:
    """
    JWT authentication dependency.

    - If AGENTGUARD_API_KEY is not set: auth is disabled, all requests pass through.
    - If set: a valid Bearer JWT is required on every /api/v1/* request.
    """
    if not auth_enabled():
        return {"sub": "anonymous", "auth_disabled": True}

    if credentials is None:
        raise AgentGuardHTTPError(
            status_code=401,
            error_code=ErrorCode.AUTH_TOKEN_REQUIRED,
            message="Bearer token required",
        )

    try:
        payload = verify_token(credentials.credentials)
    except jwt.ExpiredSignatureError:
        raise AgentGuardHTTPError(
            status_code=401,
            error_code=ErrorCode.AUTH_TOKEN_EXPIRED,
            message="Token has expired",
        )
    except jwt.InvalidTokenError:
        raise AgentGuardHTTPError(
            status_code=401,
            error_code=ErrorCode.AUTH_TOKEN_INVALID,
            message="Invalid token",
        )

    # Check Redis revocation denylist (async, skipped gracefully if Redis unavailable)
    await check_token_revocation(payload)

    return payload


async def check_rate_limit(
    request: Request,
    auth_payload: dict[str, Any] = Depends(verify_auth),
) -> None:
    """
    Rate limiting dependency.

    Keys on JWT sub when auth is enabled (accurate per-identity limiting).
    Falls back to client IP when auth is disabled or sub is absent.
    Requests with no resolvable identity are grouped under 'unknown:<path>'.
    """
    if auth_enabled() and not auth_payload.get("auth_disabled"):
        client_id = auth_payload.get("sub", "unknown")
    elif request.client is not None:
        client_id = f"ip:{request.client.host}"
    else:
        # No IP available (e.g. behind certain proxies) — scope to path to
        # avoid all unresolvable clients sharing one bucket and starving each other
        client_id = f"unknown:{request.url.path}"

    limiter = get_rate_limiter()
    if not await limiter.is_allowed(client_id):
        raise AgentGuardHTTPError(
            status_code=429,
            error_code=ErrorCode.RATE_LIMIT_EXCEEDED,
            message="Rate limit exceeded. Try again later.",
            headers={"Retry-After": str(int(os.getenv("AGENTGUARD_RATE_LIMIT_WINDOW", "60")))},
        )


@lru_cache
def get_ledger() -> EventLedger:
    """
    Return the ledger for the configured DATABASE_URL.

    Supported backends (set DATABASE_URL):
    - PostgreSQL: postgresql+asyncpg://user:pass@host:5432/db
    - SQLite (local dev): sqlite+aiosqlite:///./agentguard.db

    DATABASE_URL is required — the server will not start without it.
    """
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        raise RuntimeError(
            "DATABASE_URL is not set. "
            "For local dev run: docker compose up -d postgres && export DATABASE_URL=postgresql+asyncpg://agentguard:agentguard@localhost:5432/agentguard "
            "or set DATABASE_URL=sqlite+aiosqlite:///./agentguard.db in your .env file."
        )
    return PostgresEventLedger(db_url)


@lru_cache
def get_policy_engine() -> PolicyEngine:
    """Get the global policy engine singleton."""
    from pathlib import Path as _Path
    _cwd_policy = _Path.cwd() / "policies" / "default.yaml"
    _bundled_policy = _Path(__file__).parent.parent / "agentguard" / "policies" / "default.yaml"
    _default = str(_cwd_policy if _cwd_policy.exists() else _bundled_policy)
    policy_path = os.getenv("AGENTGUARD_POLICY_PATH", _default)
    return PolicyEngine.from_yaml(policy_path)


@lru_cache
def get_interceptor() -> Interceptor:
    """Get the global interceptor singleton."""
    return Interceptor(
        analyzer=IntentAnalyzer(backend=create_backend()),
        policy_engine=get_policy_engine(),
        event_ledger=get_ledger(),
    )


AuthDep = Annotated[dict, Depends(verify_auth)]
RateLimitDep = Annotated[None, Depends(check_rate_limit)]
LedgerDep = Annotated[EventLedger, Depends(get_ledger)]
PolicyDep = Annotated[PolicyEngine, Depends(get_policy_engine)]
InterceptorDep = Annotated[Interceptor, Depends(get_interceptor)]


# ---------------------------------------------------------------------------
# Singleton accessors for health checks (non-dependency-injection callers)
# ---------------------------------------------------------------------------

def get_ledger_instance() -> EventLedger:
    """Return the cached ledger singleton (for health checks)."""
    return get_ledger()


def get_policy_engine_instance() -> PolicyEngine:
    """Return the cached policy engine singleton (for health checks)."""
    return get_policy_engine()
