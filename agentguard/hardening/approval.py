"""
ApprovalAuthority: issues and verifies per-action signed approval tokens.

Two verification passes close the gap Dream Walking's threat model exploits:
a decision-time check alone can't detect substitution (different params
executed than were approved) or replay (the same approval reused for a
second, unauthorized action) that happens between decision and execution.
`issue()` runs at policy-decision time; `verify_and_consume()` runs again,
independently, at the point of actual tool execution.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
import structlog

from agentguard.hardening.models import ActionApproval, compute_action_hash
from agentguard.hardening.nonce_store import NonceReplayError, NonceStore

logger = structlog.get_logger(__name__)

_ALGORITHM = "HS256"


class ApprovalError(Exception):
    """Raised when an ActionApproval fails verification. Callers must treat this as a hard block."""


def _secret() -> str:
    secret = os.getenv("AGENTGUARD_APPROVAL_SECRET", "")
    if not secret:
        raise RuntimeError(
            "AGENTGUARD_APPROVAL_SECRET is not set. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    return secret


class ApprovalAuthority:
    """Issues signed ActionApproval tokens and verifies them at execution time."""

    def __init__(self, nonce_store: NonceStore) -> None:
        self._nonce_store = nonce_store

    def issue(
        self,
        tool_name: str,
        parameters: dict[str, Any],
        session_id: str,
        correlation_id: str,
        ttl_seconds: int = 30,
    ) -> ActionApproval:
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=ttl_seconds)
        action_hash = compute_action_hash(tool_name, parameters)
        approval = ActionApproval(
            action_hash=action_hash,
            session_id=session_id,
            correlation_id=correlation_id,
            issued_at=now,
            expires_at=expires_at,
        )
        payload = {
            "approval_id": approval.approval_id,
            "action_hash": approval.action_hash,
            "session_id": approval.session_id,
            "correlation_id": approval.correlation_id,
            "nonce": approval.nonce,
            "iat": now,
            "exp": expires_at,
        }
        approval.token = jwt.encode(payload, _secret(), algorithm=_ALGORITHM)
        logger.debug("approval_issued", approval_id=approval.approval_id, action_hash=action_hash[:12])
        return approval

    async def verify_and_consume(
        self,
        token: str,
        tool_name: str,
        parameters: dict[str, Any],
        session_id: str,
        correlation_id: str,
    ) -> None:
        """
        Verify signature, expiration, action binding, and session/correlation
        match, then atomically consume the nonce. Raises ApprovalError on any
        failure.
        """
        try:
            claims = jwt.decode(token, _secret(), algorithms=[_ALGORITHM])
        except jwt.ExpiredSignatureError as exc:
            raise ApprovalError("Approval expired") from exc
        except jwt.InvalidTokenError as exc:
            raise ApprovalError(f"Invalid approval token: {exc}") from exc

        expected_hash = compute_action_hash(tool_name, parameters)
        if claims["action_hash"] != expected_hash:
            raise ApprovalError(
                "Action mismatch — approval was issued for a different tool call "
                "(the substitution attack this binding prevents)"
            )
        if claims["session_id"] != session_id or claims["correlation_id"] != correlation_id:
            raise ApprovalError("Approval session/correlation mismatch")

        expires_at = datetime.fromtimestamp(claims["exp"], tz=timezone.utc)
        try:
            await self._nonce_store.consume(claims["nonce"], expires_at)
        except NonceReplayError as exc:
            raise ApprovalError(f"Replay detected: {exc}") from exc

        logger.debug("approval_verified", approval_id=claims["approval_id"])
