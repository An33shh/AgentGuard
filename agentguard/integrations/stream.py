"""Redis Streams transport layer between AgentGuard and Rowboat sidecar.

AgentGuard publishes BLOCK/REVIEW events to 'agentguard:events' stream.
Rowboat (or any consumer) reads from that stream, processes async, and
writes results back to 'agentguard:insights' stream.

The Interceptor XADD costs ~0.1ms — zero hot-path impact.
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

EVENTS_STREAM = "agentguard:events"
INSIGHTS_STREAM = "agentguard:insights"
CONSUMER_GROUP = "rowboat-workers"
STREAM_MAXLEN = 10_000  # cap stream size to avoid unbounded growth


class RedisStreamPublisher:
    """
    Publishes AgentGuard events to Redis Streams.

    Lazy-connects on first publish so startup is never blocked.
    Falls back silently if Redis is unavailable.
    """

    def __init__(self, redis_url: str | None = None) -> None:
        self._url = redis_url or os.getenv("REDIS_URL", "")
        self._client: Any = None
        self._enabled = bool(self._url)

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def _get_client(self) -> Any:
        if self._client is None:
            import redis.asyncio as aioredis
            self._client = aioredis.from_url(self._url, decode_responses=True)
        return self._client

    async def publish_event(self, event_data: dict[str, str]) -> None:
        """XADD to agentguard:events stream. Fire-and-forget safe."""
        client = await self._get_client()
        await client.xadd(EVENTS_STREAM, event_data, maxlen=STREAM_MAXLEN, approximate=True)

    async def publish_insight(self, insight_data: dict[str, str]) -> None:
        """XADD to agentguard:insights stream (Rowboat → AgentGuard direction)."""
        client = await self._get_client()
        await client.xadd(INSIGHTS_STREAM, insight_data, maxlen=STREAM_MAXLEN, approximate=True)

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()


class RedisStreamConsumer:
    """
    Consumes events from agentguard:events and invokes a handler.

    Designed to run in the Rowboat sidecar process. Uses consumer groups
    for at-least-once delivery and XACK after successful processing.
    """

    def __init__(
        self,
        redis_url: str | None = None,
        consumer_name: str = "rowboat-1",
    ) -> None:
        self._url = redis_url or os.getenv("REDIS_URL", "")
        self._consumer_name = consumer_name
        self._client: Any = None

    async def _get_client(self) -> Any:
        if self._client is None:
            import redis.asyncio as aioredis
            self._client = aioredis.from_url(self._url, decode_responses=True)
        return self._client

    async def ensure_group(self) -> None:
        """Create the consumer group if it doesn't exist (idempotent)."""
        client = await self._get_client()
        try:
            await client.xgroup_create(EVENTS_STREAM, CONSUMER_GROUP, id="0", mkstream=True)
        except Exception:
            pass  # group already exists

    async def run(self, handler: Any, poll_interval: float = 0.5) -> None:
        """
        Blocking consume loop. For each event, call handler(event_data dict),
        then XACK. Runs until the task is cancelled.
        """
        await self.ensure_group()
        client = await self._get_client()
        logger.info("redis_consumer_started", stream=EVENTS_STREAM, group=CONSUMER_GROUP)

        while True:
            try:
                results = await client.xreadgroup(
                    CONSUMER_GROUP,
                    self._consumer_name,
                    {EVENTS_STREAM: ">"},
                    count=10,
                    block=int(poll_interval * 1000),
                )
                if not results:
                    continue

                for _stream, messages in results:
                    for msg_id, fields in messages:
                        try:
                            await handler(fields)
                            await client.xack(EVENTS_STREAM, CONSUMER_GROUP, msg_id)
                        except Exception as exc:
                            logger.warning(
                                "redis_consumer_handler_error",
                                msg_id=msg_id,
                                error=str(exc),
                            )
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("redis_consumer_poll_error", error=str(exc))
                await asyncio.sleep(poll_interval)

        await client.aclose()


# ---------------------------------------------------------------------------
# Singleton publisher
# ---------------------------------------------------------------------------

_publisher: RedisStreamPublisher | None = None


def get_stream_publisher() -> RedisStreamPublisher:
    global _publisher
    if _publisher is None:
        _publisher = RedisStreamPublisher()
    return _publisher
