"""
Rowboat sidecar worker.

Run this as a separate process alongside the AgentGuard API:

    python -m agentguard.integrations.rowboat_worker

It reads AgentGuard security events from the Redis 'agentguard:events' stream,
runs multi-agent triage via Rowboat, and writes insights back to Redis
'agentguard:insights' stream AND the in-process InsightsStore.

When colocated with the API (same host), the InsightsStore write means the
/api/v1/insights endpoint serves Rowboat results with no extra hop.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys

import structlog

from agentguard.integrations.insights import get_insights_store
from agentguard.integrations.rowboat import get_rowboat_client
from agentguard.integrations.stream import get_stream_publisher, RedisStreamConsumer
from agentguard.telemetry.logger import configure_logging

logger = structlog.get_logger(__name__)


async def handle_event(fields: dict[str, str]) -> None:
    """Process one event from the Redis stream."""
    rowboat = get_rowboat_client()
    if not rowboat.enabled:
        logger.warning("rowboat_not_configured", msg="Skipping event — Rowboat credentials missing")
        return

    insight = await rowboat.triage_event(fields)
    store = get_insights_store()
    store.put(insight)

    # Publish insight back to Redis so other consumers (dashboard, alerting) can react
    publisher = get_stream_publisher()
    if publisher.enabled:
        await publisher.publish_insight({
            "event_id": insight.event_id,
            "analysis": insight.analysis,
            "attack_patterns": json.dumps(insight.attack_patterns),
            "confidence": str(insight.confidence),
            "workflow": insight.workflow.value,
            "created_at": insight.created_at.isoformat(),
        })

    logger.info(
        "insight_generated",
        event_id=insight.event_id,
        attack_patterns=insight.attack_patterns,
        confidence=insight.confidence,
    )


async def main() -> None:
    configure_logging(log_level=os.getenv("AGENTGUARD_LOG_LEVEL", "INFO"))
    logger.info("rowboat_worker_starting")

    consumer = RedisStreamConsumer(
        consumer_name=os.getenv("ROWBOAT_WORKER_NAME", "rowboat-1"),
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

    logger.info("rowboat_worker_stopped")


if __name__ == "__main__":
    asyncio.run(main())
