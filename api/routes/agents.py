"""Agent profile and knowledge graph endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from agentguard.core.errors import AgentGuardHTTPError, ErrorCode
from agentguard.integrations.enrichment import get_enrichment_client
from api.dependencies import LedgerDep

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])


def _apply_display_names(profiles: list) -> None:
    """
    Populate display_name on every profile.

    get_display_name() is synchronous and O(1) on cache hit — returns the cached
    name (rule-based or AI-generated) immediately. On a cache miss it seeds the
    cache with a rule-based name and fires a background Claude task. Either way
    this function adds zero I/O latency to the HTTP response.
    """
    client = get_enrichment_client()
    for p in profiles:
        p.display_name = client.get_display_name(p.agent_id, p.agent_goal, p.framework, p.is_registered)


@router.get("")
async def list_agents(ledger: LedgerDep) -> dict:
    """List all observed agents with aggregated profiles."""
    profiles = await ledger.list_agents()
    _apply_display_names(profiles)
    return {
        "agents": [p.model_dump(mode="json") for p in profiles],
        "total": len(profiles),
    }


@router.get("/{agent_id}")
async def get_agent(agent_id: str, ledger: LedgerDep) -> dict:
    """Get full profile for a single agent."""
    profile = await ledger.get_agent_profile(agent_id)
    if not profile:
        raise AgentGuardHTTPError(404, ErrorCode.NOT_FOUND, "Agent not found")
    _apply_display_names([profile])
    return profile.model_dump(mode="json")


@router.get("/{agent_id}/graph")
async def get_agent_graph(agent_id: str, ledger: LedgerDep) -> dict:
    """Get knowledge graph nodes and edges for a specific agent."""
    profile = await ledger.get_agent_profile(agent_id)
    if not profile:
        raise AgentGuardHTTPError(404, ErrorCode.NOT_FOUND, "Agent not found")
    graph = await ledger.get_agent_graph(agent_id)
    return graph.model_dump(mode="json")
