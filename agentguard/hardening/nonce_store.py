"""Nonce store for single-use replay rejection of ActionApproval tokens."""

from __future__ import annotations

import abc
import asyncio
from datetime import UTC, datetime
from typing import Any


class NonceReplayError(Exception):
    """Raised when a nonce has already been consumed — signals a replay attempt."""


class NonceStore(abc.ABC):
    @abc.abstractmethod
    async def consume(self, nonce: str, expires_at: datetime) -> None:
        """
        Atomically mark a nonce as used.

        Raises NonceReplayError if the nonce was already consumed.
        """


class InMemoryNonceStore(NonceStore):
    """
    Process-local nonce store.

    Sufficient for a single-process research prototype. A multi-worker
    production deployment would need a shared backing store (e.g. Redis
    SETNX, mirroring the revocation store in agentguard/auth/jwt_utils.py)
    so a nonce consumed on one worker is visible to all others.
    """

    def __init__(self) -> None:
        self._used: dict[str, datetime] = {}
        self._lock = asyncio.Lock()

    async def consume(self, nonce: str, expires_at: datetime) -> None:
        async with self._lock:
            self._purge_expired()
            if nonce in self._used:
                raise NonceReplayError(f"Nonce already consumed: {nonce}")
            self._used[nonce] = expires_at

    def _purge_expired(self) -> None:
        now = datetime.now(UTC)
        expired = [n for n, exp in self._used.items() if exp < now]
        for n in expired:
            del self._used[n]


class RedisNonceStore(NonceStore):
    """
    Redis-backed nonce store — shared across processes and workers, unlike
    InMemoryNonceStore. Uses atomic SET NX EX (set-if-not-exists with a
    TTL) for consume-once semantics, so two separate processes racing to
    consume the same nonce can't both succeed: Redis resolves the race,
    not application code.
    """

    def __init__(self, redis_url: str) -> None:
        self._redis_url = redis_url
        self._client: Any | None = None

    def _get_client(self) -> Any:
        if self._client is None:
            import redis.asyncio as aioredis
            self._client = aioredis.from_url(
                self._redis_url,
                socket_connect_timeout=1,
                max_connections=20,
            )
        return self._client

    async def consume(self, nonce: str, expires_at: datetime) -> None:
        client = self._get_client()
        ttl_seconds = max(1, int((expires_at - datetime.now(UTC)).total_seconds()))
        was_set = await client.set(f"agentguard:nonce:{nonce}", "1", nx=True, ex=ttl_seconds)
        if not was_set:
            raise NonceReplayError(f"Nonce already consumed: {nonce}")
