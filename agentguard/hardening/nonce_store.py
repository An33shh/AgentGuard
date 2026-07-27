"""Nonce store for single-use replay rejection of ActionApproval tokens."""

from __future__ import annotations

import abc
import asyncio
from datetime import datetime, timezone


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
        now = datetime.now(timezone.utc)
        expired = [n for n, exp in self._used.items() if exp < now]
        for n in expired:
            del self._used[n]
