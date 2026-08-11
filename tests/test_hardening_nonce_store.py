"""
Integration tests for RedisNonceStore against a real Redis instance.

Skipped entirely if REDIS_URL isn't configured or Redis isn't reachable —
these are integration tests, not unit tests, and require
`docker compose up -d redis` (see docker-compose.yml) to run.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
import redis.exceptions

from agentguard.hardening.nonce_store import NonceReplayError, RedisNonceStore

REDIS_URL = os.getenv("REDIS_URL", "")

pytestmark = pytest.mark.skipif(not REDIS_URL, reason="REDIS_URL not configured")


async def _redis_reachable() -> bool:
    try:
        import redis.asyncio as aioredis
        client = aioredis.from_url(REDIS_URL, socket_connect_timeout=1)
        await client.ping()
        await client.aclose()
        return True
    except Exception:
        return False


@pytest.fixture(autouse=True)
async def _skip_if_unreachable():
    if not await _redis_reachable():
        pytest.skip(f"Redis at {REDIS_URL} is not reachable")


@pytest.fixture
def expires_at() -> datetime:
    return datetime.now(UTC) + timedelta(seconds=30)


class TestRedisNonceStoreBasic:
    async def test_consume_once_succeeds(self, expires_at: datetime) -> None:
        import uuid
        store = RedisNonceStore(REDIS_URL)
        await store.consume(f"nonce-{uuid.uuid4().hex}", expires_at)

    async def test_consume_twice_raises_replay(self, expires_at: datetime) -> None:
        import uuid
        store = RedisNonceStore(REDIS_URL)
        nonce = f"nonce-{uuid.uuid4().hex}"
        await store.consume(nonce, expires_at)
        with pytest.raises(NonceReplayError):
            await store.consume(nonce, expires_at)


class TestRedisNonceStoreCrossInstance:
    """The property InMemoryNonceStore explicitly can't provide: a nonce
    consumed via one process/instance is visible to a completely separate
    instance, because both talk to the same Redis backing store."""

    async def test_replay_rejected_across_independent_store_instances(
        self, expires_at: datetime
    ) -> None:
        import uuid
        nonce = f"nonce-{uuid.uuid4().hex}"

        store_a = RedisNonceStore(REDIS_URL)  # simulates worker/process A
        store_b = RedisNonceStore(REDIS_URL)  # simulates a completely independent worker/process B

        await store_a.consume(nonce, expires_at)
        with pytest.raises(NonceReplayError):
            await store_b.consume(nonce, expires_at)

    async def test_concurrent_consume_across_independent_instances_exactly_one_wins(
        self, expires_at: datetime
    ) -> None:
        """
        The real-world version of the race condition: multiple independent
        RedisNonceStore instances (simulating separate worker processes),
        all racing to consume the SAME nonce at the same time. Redis's
        atomic SET NX must resolve the race, not application code — this
        is exactly what a multi-worker deployment under load looks like.
        """
        import asyncio
        import uuid

        nonce = f"nonce-{uuid.uuid4().hex}"
        stores = [RedisNonceStore(REDIS_URL) for _ in range(10)]

        results = await asyncio.gather(
            *[store.consume(nonce, expires_at) for store in stores],
            return_exceptions=True,
        )
        successes = [r for r in results if r is None]
        replays = [r for r in results if isinstance(r, NonceReplayError)]
        assert len(successes) == 1
        assert len(replays) == 9


class TestRedisNonceStoreFailureMode:
    """
    Security posture: what happens when Redis itself is unreachable.
    consume() must propagate a real error rather than silently succeeding
    (which would make an infra outage indistinguishable from "nonce is
    fresh" and defeat replay protection exactly when it matters most).
    """

    async def test_unreachable_redis_raises_not_silently_succeeds(
        self, expires_at: datetime
    ) -> None:
        import uuid
        # Port 1 is not a Redis instance — connection will fail fast.
        store = RedisNonceStore("redis://localhost:1/0")
        with pytest.raises(redis.exceptions.RedisError):
            await store.consume(f"nonce-{uuid.uuid4().hex}", expires_at)
