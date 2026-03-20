"""JWT token creation and verification for AgentGuard API authentication.

Token revocation:
  Each token carries a `jti` (JWT ID) claim. Revoked JTIs are stored in Redis
  under the key agentguard:revoked:{jti} with a TTL equal to the token's remaining
  lifetime. Revocation requires REDIS_URL to be configured.

  If Redis is unavailable, revocation checks are skipped (logged as a warning).
  Tokens without a `jti` claim (issued before revocation support) are still valid
  but cannot be explicitly revoked.
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from typing import Any

import jwt

_ALGORITHM = "HS256"
logger = logging.getLogger(__name__)

# Warn about missing Redis for revocation only once
_revocation_redis_warned = False


def _secret() -> str:
    secret = os.getenv("AGENTGUARD_JWT_SECRET", "")
    if not secret:
        raise RuntimeError(
            "AGENTGUARD_JWT_SECRET is not set. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    return secret


def token_expire_seconds() -> int:
    """Return the configured token lifetime in seconds."""
    return int(os.getenv("AGENTGUARD_JWT_EXPIRE_SECONDS", "3600"))


def create_access_token(data: dict[str, Any]) -> str:
    """Create a signed JWT access token with a unique jti claim."""
    now = int(time.time())
    payload = {
        **data,
        "iat": now,
        "exp": now + token_expire_seconds(),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, _secret(), algorithm=_ALGORITHM)


def verify_token(token: str) -> dict[str, Any]:
    """
    Verify and decode a JWT token (signature + expiry only).

    Raises jwt.InvalidTokenError (or subclass) on any failure:
      - jwt.ExpiredSignatureError  — token has expired
      - jwt.InvalidSignatureError  — wrong secret
      - jwt.DecodeError            — malformed token

    Note: revocation checks (jti denylist) are async and performed separately
    via check_token_revocation() in the async request path.
    """
    return jwt.decode(token, _secret(), algorithms=[_ALGORITHM])


async def check_token_revocation(payload: dict[str, Any]) -> None:
    """
    Async revocation check — consults Redis jti denylist.

    Raises AgentGuardHTTPError(401, AUTH_TOKEN_REVOKED) if revoked.
    Skips silently (with a one-time warning) if Redis is unavailable.
    Tokens without a jti claim are not revocable and pass through.
    """
    global _revocation_redis_warned

    jti = payload.get("jti")
    if not jti:
        return  # pre-revocation token, cannot be explicitly revoked

    redis_url = os.getenv("REDIS_URL", "")
    if not redis_url:
        return  # no Redis configured, revocation not available

    try:
        import redis.asyncio as aioredis
        client = aioredis.from_url(redis_url, socket_connect_timeout=1)
        is_revoked = await client.exists(f"agentguard:revoked:{jti}")
        await client.aclose()
        if is_revoked:
            from agentguard.core.errors import AgentGuardHTTPError, ErrorCode
            raise AgentGuardHTTPError(
                401,
                ErrorCode.AUTH_TOKEN_REVOKED,
                "Token has been revoked",
            )
    except Exception as exc:
        # Re-raise AgentGuardHTTPError (token is actually revoked)
        try:
            from agentguard.core.errors import AgentGuardHTTPError
            if isinstance(exc, AgentGuardHTTPError):
                raise
        except ImportError:
            pass

        if not _revocation_redis_warned:
            logger.warning("jwt_revocation_redis_unavailable: %s", exc)
            _revocation_redis_warned = True


def auth_enabled() -> bool:
    """Auth is enabled only when AGENTGUARD_API_KEY is configured."""
    return bool(os.getenv("AGENTGUARD_API_KEY"))


def validate_auth_config() -> None:
    """
    Fail fast at startup if the auth configuration is inconsistent.

    Rules:
      - AGENTGUARD_API_KEY and AGENTGUARD_JWT_SECRET must both be set or both absent.
      - AGENTGUARD_JWT_SECRET must be at least 32 bytes when auth is enabled.
    """
    api_key = os.getenv("AGENTGUARD_API_KEY", "")
    jwt_secret = os.getenv("AGENTGUARD_JWT_SECRET", "")

    if bool(api_key) != bool(jwt_secret):
        raise RuntimeError(
            "Inconsistent auth configuration: "
            "AGENTGUARD_API_KEY and AGENTGUARD_JWT_SECRET must both be set or both left unset. "
            "Generate a secret with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )

    if api_key and len(jwt_secret) < 32:
        raise RuntimeError(
            f"AGENTGUARD_JWT_SECRET is too short ({len(jwt_secret)} bytes). "
            "Minimum 32 bytes required for HS256. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
