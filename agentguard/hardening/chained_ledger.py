"""Hash-chained, tamper-evident wrapper around an EventLedger."""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any

import structlog

from agentguard.core.models import Event

logger = structlog.get_logger(__name__)

GENESIS_HASH = "0" * 64


def _event_content_hash(event: Event, prev_hash: str) -> str:
    """
    Hash of (prev_hash + canonical event fields).

    Any modification to a prior event changes every hash computed after it,
    so tampering is detectable by recomputing the chain from stored field
    values and comparing against the persisted event_hash/prev_event_hash.
    A hash chain resident purely in one database offers no protection
    against an attacker who can rewrite the entire chain forward from the
    point of tampering — that requires an external anchor (a separately
    published head hash, a signed log) which is out of scope for this
    prototype and noted as a limitation for the paper-2 evaluation.
    """
    payload = {
        "prev_hash": prev_hash,
        "event_id": event.event_id,
        "session_id": event.session_id,
        "agent_id": event.agent_id,
        "action_hash": hashlib.sha256(
            json.dumps(
                {"tool": event.action.tool_name, "params": event.action.parameters},
                sort_keys=True,
                default=str,
            ).encode()
        ).hexdigest(),
        "decision": event.decision.value,
        "correlation_id": event.correlation_id,
        "initiating_principal": event.initiating_principal,
        "timestamp": event.timestamp.isoformat(),
    }
    canonical = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


class ChainBrokenError(Exception):
    """Raised by verify_chain() when a recomputed hash doesn't match the persisted one."""


class HashChainedEventLedger:
    """
    Decorates any EventLedger with a per-session hash chain.

    Wraps rather than subclasses EventLedger: read methods delegate via
    __getattr__, so this is a drop-in decorator over InMemoryEventLedger or
    PostgresEventLedger without duplicating their query logic. The chain
    fields (event_hash, prev_event_hash) are set directly on the Event
    object before delegating to the inner ledger, so they're persisted
    exactly like any other event field — no separate side-store needed for
    verification to work after a process restart.
    """

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self._lock = asyncio.Lock()
        self._last_hash_cache: dict[str, str] = {}

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    async def append(self, event: Event) -> None:
        async with self._lock:
            prev_hash = await self._get_last_hash(event.session_id)
            event.prev_event_hash = prev_hash
            event.event_hash = _event_content_hash(event, prev_hash)
            await self._inner.append(event)
            self._last_hash_cache[event.session_id] = event.event_hash
        logger.debug(
            "event_chained", event_id=event.event_id, event_hash=event.event_hash[:12]
        )

    async def _get_last_hash(self, session_id: str) -> str:
        cached = self._last_hash_cache.get(session_id)
        if cached is not None:
            return cached
        timeline = await self._inner.get_timeline(session_id)
        if timeline and timeline[-1].event_hash:
            return timeline[-1].event_hash
        return GENESIS_HASH

    async def verify_chain(self, session_id: str) -> bool:
        """
        Recompute the hash chain for a session's events in timeline order and
        confirm it matches the persisted event_hash/prev_event_hash fields.

        Returns True if intact; raises ChainBrokenError identifying the first
        broken event if tampering (modification, deletion, or reordering) is
        detected.
        """
        events = await self._inner.get_timeline(session_id)
        prev_hash = GENESIS_HASH
        for event in events:
            if event.prev_event_hash != prev_hash:
                raise ChainBrokenError(
                    f"prev_hash mismatch at event {event.event_id}: "
                    f"expected continuity from {prev_hash[:12]}, found {event.prev_event_hash[:12]}"
                )
            expected = _event_content_hash(event, prev_hash)
            if event.event_hash != expected:
                raise ChainBrokenError(
                    f"content hash mismatch at event {event.event_id} — "
                    "event was modified after being chained"
                )
            prev_hash = event.event_hash
        return True
