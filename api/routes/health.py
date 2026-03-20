"""Health check endpoints — liveness and readiness probes."""

from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime, timezone

from fastapi import APIRouter
from fastapi.responses import JSONResponse

APP_VERSION = "0.9.0"

router = APIRouter(prefix="/api/v1", tags=["health"])


@router.get("/health")
async def liveness() -> dict:
    """Kubernetes liveness probe — always fast, no dependency checks."""
    return {
        "status": "healthy",
        "version": APP_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/readiness")
async def readiness():
    """Kubernetes readiness probe — checks all dependencies."""
    components = {}

    # DB check
    components["database"] = await _check_database()

    # Redis check
    components["redis"] = await _check_redis()

    # Policy engine check
    components["policy"] = _check_policy()

    # Analyzer check (no live call)
    components["analyzer"] = _check_analyzer()

    # Determine overall status
    statuses = [c["status"] for c in components.values()]
    if "unhealthy" in statuses:
        overall = "unhealthy"
    elif "degraded" in statuses:
        overall = "degraded"
    else:
        overall = "healthy"

    status_code = 503 if overall == "unhealthy" else 200
    return JSONResponse(
        status_code=status_code,
        content={
            "status": overall,
            "version": APP_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": components,
        },
    )


async def _check_database() -> dict:
    try:
        from api.dependencies import get_ledger_instance
        ledger = get_ledger_instance()
        from agentguard.ledger.db import PostgresEventLedger
        if not isinstance(ledger, PostgresEventLedger):
            return {"status": "healthy", "note": "in-memory ledger"}
        t0 = time.monotonic()
        async with ledger._engine.connect() as conn:
            from sqlalchemy import text
            await conn.execute(text("SELECT 1"))
        latency_ms = (time.monotonic() - t0) * 1000
        return {"status": "healthy", "latency_ms": round(latency_ms, 2)}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}


async def _check_redis() -> dict:
    try:
        redis_url = os.getenv("REDIS_URL")
        if not redis_url:
            return {"status": "degraded", "note": "REDIS_URL not configured"}
        import redis.asyncio as aioredis
        t0 = time.monotonic()
        client = aioredis.from_url(redis_url, socket_connect_timeout=1)
        await asyncio.wait_for(client.ping(), timeout=1.0)
        await client.aclose()
        latency_ms = (time.monotonic() - t0) * 1000
        return {"status": "healthy", "latency_ms": round(latency_ms, 2)}
    except Exception as e:
        return {"status": "degraded", "error": str(e)}


def _check_policy() -> dict:
    try:
        from api.dependencies import get_policy_engine_instance
        engine = get_policy_engine_instance()
        if engine._config is None:
            return {"status": "unhealthy", "error": "policy not loaded"}
        return {
            "status": "healthy",
            "name": engine._config.name,
            "threshold": engine._config.risk_threshold,
        }
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}


def _check_analyzer() -> dict:
    model = os.getenv("AGENTGUARD_MODEL", "claude-sonnet-4-6")
    has_key = bool(os.getenv("ANTHROPIC_API_KEY"))
    if not has_key:
        return {"status": "degraded", "note": "ANTHROPIC_API_KEY not set"}
    return {"status": "healthy", "model": model}
