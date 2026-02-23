"""Health check endpoint."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter

router = APIRouter(prefix="/api/v1", tags=["health"])


@router.get("/health")
async def health() -> dict:
    return {
        "status": "healthy",
        "service": "agentguard",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
