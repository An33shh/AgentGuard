"""Agent profile and knowledge graph endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from api.dependencies import LedgerDep

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])


@router.get("")
async def list_agents(ledger: LedgerDep) -> dict:
    """List all observed agents with aggregated profiles."""
    profiles = await ledger.list_agents()
    return {
        "agents": [p.model_dump(mode="json") for p in profiles],
        "total": len(profiles),
    }


@router.get("/{agent_id}")
async def get_agent(agent_id: str, ledger: LedgerDep) -> dict:
    """Get full profile for a single agent."""
    profile = await ledger.get_agent_profile(agent_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Agent not found")
    return profile.model_dump(mode="json")


@router.get("/{agent_id}/graph")
async def get_agent_graph(agent_id: str, ledger: LedgerDep) -> dict:
    """Get knowledge graph nodes and edges for a specific agent."""
    profile = await ledger.get_agent_profile(agent_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Agent not found")
    graph = await ledger.get_agent_graph(agent_id)
    return graph.model_dump(mode="json")
