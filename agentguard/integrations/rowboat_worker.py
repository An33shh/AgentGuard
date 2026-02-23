"""Async enrichment sidecar worker.

Run as a separate process alongside the AgentGuard API:

    python -m agentguard.integrations.rowboat_worker

Reads BLOCK/REVIEW events from the Redis 'agentguard:events' stream,
runs async Claude security triage, and writes insights back to the
InsightsStore and 'agentguard:insights' Redis stream.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal

import structlog

from agentguard.integrations.enrichment import get_enrichment_client
from agentguard.integrations.insights import get_insights_store
from agentguard.integrations.stream import get_stream_publisher, RedisStreamConsumer
from agentguard.telemetry.logger import configure_logging

logger = structlog.get_logger(__name__)


async def handle_event(fields: dict[str, str]) -> None:
    """Process one event from the Redis stream."""
    client = get_enrichment_client()
    if not client.enabled:
        logger.warning("enrichment_disabled", msg="Skipping — ANTHROPIC_API_KEY not set")
        return

    insight = await client.triage_event(fields)
    store = get_insights_store()
    store.put(insight)

    publisher = get_stream_publisher()
    if publisher.enabled:
        await publisher.publish_insight({
            "event_id": insight.event_id,
            "analysis": insight.analysis,
            "attack_patterns": json.dumps(insight.attack_patterns),
            "confidence": str(insight.confidence),
            "severity": insight.severity,
            "recommended_action": insight.recommended_action,
            "false_positive_likelihood": str(insight.false_positive_likelihood),
            "created_at": insight.created_at.isoformat(),
        })

    logger.info(
        "insight_generated",
        event_id=insight.event_id,
        attack_patterns=insight.attack_patterns,
        confidence=insight.confidence,
        severity=insight.severity,
    )


async def main() -> None:
    configure_logging(log_level=os.getenv("AGENTGUARD_LOG_LEVEL", "INFO"))
    logger.info("enrichment_worker_starting")

    consumer = RedisStreamConsumer(
        consumer_name=os.getenv("ENRICHMENT_WORKER_NAME", "enrichment-1"),
    )

    loop = asyncio.get_running_loop()
    stop = loop.create_future()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set_result, None)

    worker_task = asyncio.create_task(consumer.run(handle_event))

    await stop
    worker_task.cancel()
    try:
        await worker_task
    except asyncio.CancelledError:
        pass

    logger.info("enrichment_worker_stopped")


if __name__ == "__main__":
    asyncio.run(main())
