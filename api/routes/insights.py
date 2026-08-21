"""Security enrichment insights endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Query

from agentguard.core.errors import AgentGuardHTTPError, ErrorCode
from agentguard.integrations.enrichment import get_enrichment_client
from agentguard.integrations.insights import get_insights_store

router = APIRouter(prefix="/api/v1/insights", tags=["insights"])


@router.get("")
async def list_insights(limit: int = Query(50, ge=1, le=500)) -> dict:
    store = get_insights_store()
    items = store.list_recent(limit=limit)
    return {
        "insights": [store.to_dict(i) for i in reversed(items)],
        "total": len(store),
        "enrichment_enabled": get_enrichment_client().enabled,
    }


@router.get("/{event_id}")
async def get_insight(event_id: str) -> dict:
    store = get_insights_store()
    insight = store.get(event_id)
    if not insight:
        raise AgentGuardHTTPError(404, ErrorCode.NOT_FOUND, "No insight available for this event yet")
    return store.to_dict(insight)
