"""Authentication endpoints — API key exchange for JWT access token."""

from __future__ import annotations

import hmac
import os
import time
from typing import Any  # used for body: dict[str, Any]

import jwt as _jwt

from fastapi import APIRouter, Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from agentguard.auth.jwt_utils import auth_enabled, check_token_revocation, create_access_token, token_expire_seconds, verify_token
from agentguard.auth.rate_limiter import get_rate_limiter
from agentguard.core.errors import AgentGuardHTTPError, ErrorCode

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

_bearer = HTTPBearer(auto_error=False)


async def _get_auth_payload(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict:
    """Extract and verify the JWT from the Authorization header."""
    if credentials is None:
        raise AgentGuardHTTPError(401, ErrorCode.AUTH_TOKEN_REQUIRED, "Bearer token required")
    try:
        payload = verify_token(credentials.credentials)
    except _jwt.ExpiredSignatureError:
        raise AgentGuardHTTPError(401, ErrorCode.AUTH_TOKEN_EXPIRED, "Token has expired")
    except _jwt.InvalidTokenError:
        raise AgentGuardHTTPError(401, ErrorCode.AUTH_TOKEN_INVALID, "Invalid token")
    await check_token_revocation(payload)
    return payload

# Separate, unauthenticated rate limiter for the token endpoint
# Prevents brute-force of AGENTGUARD_API_KEY
_AUTH_RATE_LIMIT = int(os.getenv("AGENTGUARD_AUTH_RATE_LIMIT", "10"))  # 10 attempts/min
_AUTH_RATE_WINDOW = float(os.getenv("AGENTGUARD_AUTH_RATE_WINDOW", "60"))


async def _auth_rate_limit(request: Request) -> None:
    limiter = get_rate_limiter()
    client_id = request.client.host if request.client else "unknown"
    allowed = await limiter.is_allowed(f"auth:{client_id}", limit=_AUTH_RATE_LIMIT, window=_AUTH_RATE_WINDOW)
    if not allowed:
        raise AgentGuardHTTPError(
            429,
            ErrorCode.RATE_LIMIT_EXCEEDED,
            "Too many authentication attempts. Try again later.",
            headers={"Retry-After": str(int(_AUTH_RATE_WINDOW))},
        )


@router.post("/token", dependencies=[Depends(_auth_rate_limit)])
async def get_token(body: dict[str, Any]) -> dict:
    """
    Exchange an API key for a short-lived JWT access token.

    Request body: {"api_key": "<your key>"}
    Response:     {"access_token": "...", "token_type": "bearer", "expires_in": 3600}
    """
    if not auth_enabled():
        raise AgentGuardHTTPError(
            501,
            ErrorCode.INTERNAL_ERROR,
            "Authentication is not enabled. Set AGENTGUARD_API_KEY to enable it.",
        )

    provided = body.get("api_key", "")
    expected = os.getenv("AGENTGUARD_API_KEY", "")

    # Constant-time comparison to prevent timing attacks
    if not provided or not hmac.compare_digest(provided.encode(), expected.encode()):
        raise AgentGuardHTTPError(401, ErrorCode.AUTH_BAD_CREDENTIALS, "Invalid API key")

    token = create_access_token({"sub": "api_client"})
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": token_expire_seconds(),
    }


@router.post("/revoke")
async def revoke_token(
    payload: dict = Depends(_get_auth_payload),
) -> dict:
    """Revoke the current JWT. Requires the token being revoked."""
    jti = payload.get("jti")
    if not jti:
        raise AgentGuardHTTPError(
            400,
            ErrorCode.VALIDATION_ERROR,
            "Token has no jti claim (issued before revocation support)",
        )

    exp = payload.get("exp", 0)
    ttl = max(int(exp - time.time()), 1)

    try:
        redis_url = os.getenv("REDIS_URL")
        if not redis_url:
            raise AgentGuardHTTPError(
                503,
                ErrorCode.INTERNAL_ERROR,
                "Token revocation requires Redis (REDIS_URL not configured)",
            )
        import redis.asyncio as aioredis
        client = aioredis.from_url(redis_url)
        await client.setex(f"agentguard:revoked:{jti}", ttl, "1")
        await client.aclose()
        return {"revoked": True, "jti": jti}
    except AgentGuardHTTPError:
        raise
    except Exception as e:
        raise AgentGuardHTTPError(500, ErrorCode.INTERNAL_ERROR, f"Failed to revoke token: {e}")
