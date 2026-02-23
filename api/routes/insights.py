"""Rowboat security insights endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from agentguard.integrations.insights import get_insights_store
from agentguard.integrations.rowboat import get_rowboat_client

router = APIRouter(prefix="/api/v1/insights", tags=["insights"])


@router.get("")
async def list_insights(limit: int = 50) -> dict:
    store = get_insights_store()
    items = store.list_recent(limit=limit)
    return {
        "insights": [store.to_dict(i) for i in reversed(items)],
        "total": len(items),
        "rowboat_enabled": get_rowboat_client().enabled,
    }


@router.get("/{event_id}")
async def get_insight(event_id: str) -> dict:
    store = get_insights_store()
    insight = store.get(event_id)
    if not insight:
        raise HTTPException(status_code=404, detail="No insight available for this event yet")
    return store.to_dict(insight)


@router.post("/policy")
async def generate_policy(body: dict) -> dict:
    """Generate a tailored security policy for an agent using Rowboat."""
    rowboat = get_rowboat_client()
    if not rowboat.enabled:
        raise HTTPException(status_code=503, detail="Rowboat integration not configured")

    description = body.get("agent_description", "")
    if not description:
        raise HTTPException(status_code=400, detail="agent_description is required")

    yaml_policy = await rowboat.generate_policy(
        agent_description=description,
        existing_policy=body.get("existing_policy"),
    )
    return {"policy_yaml": yaml_policy, "generated_by": "rowboat"}
