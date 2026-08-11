"""
Data models for AgentGuard's paper-2 hardening layer.

AgentGuard authenticates at the session level (JWT) but not at the level of
an individual protected action. These models bind an authorization decision
to the exact action instance it approved, so the Initiator, Executor, and
Credential Principal implied by a signed approval cannot be silently
substituted between decision time and execution time — the mechanism
Dream Walking's threat model exploits to collapse those three identities
into one in the audit trail.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


def compute_action_hash(tool_name: str, parameters: dict[str, Any]) -> str:
    """
    Deterministic hash binding an approval to an exact action instance.

    Canonical JSON (sorted keys) makes the hash stable regardless of dict
    insertion order, so re-serializing the same logical action always
    produces the same hash.
    """
    canonical = json.dumps(
        {"tool_name": tool_name, "parameters": parameters},
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


class ActionApproval(BaseModel):
    """
    A signed, single-use authorization for one specific action instance.

    `token` carries the signed JWT encoding of the fields below; the model
    itself is also kept around server-side (in the Interceptor's pending
    set) so the token can be verified again at execution time without
    re-deriving it from the Event.
    """

    model_config = {"extra": "forbid"}

    approval_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action_hash: str
    session_id: str
    correlation_id: str
    nonce: str = Field(default_factory=lambda: uuid.uuid4().hex)
    issued_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime
    token: str = ""


class HardeningConfig(BaseModel):
    model_config = {"extra": "forbid"}

    enabled: bool = False
    approval_ttl_seconds: int = 30
