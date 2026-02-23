"""Event and timeline API endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from agentguard.core.models import Decision, Event, TimelineSummary
from api.dependencies import LedgerDep

router = APIRouter(prefix="/api/v1", tags=["events"])


@router.get("/events", response_model=list[Event])
async def list_events(
    ledger: LedgerDep,
    session_id: str | None = Query(None),
    decision: Decision | None = Query(None),
    min_risk: float | None = Query(None, ge=0.0, le=1.0),
    max_risk: float | None = Query(None, ge=0.0, le=1.0),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[Event]:
    """List events with optional filters."""
    return await ledger.list_events(
        session_id=session_id,
        decision=decision,
        min_risk=min_risk,
        max_risk=max_risk,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
    )


@router.get("/events/{event_id}", response_model=Event)
async def get_event(event_id: str, ledger: LedgerDep) -> Event:
    """Get full forensic detail for a single event."""
    event = await ledger.get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found")
    return event


@router.get("/timeline", response_model=list[Event])
async def get_timeline(
    ledger: LedgerDep,
    session_id: str = Query(..., description="Session ID to get timeline for"),
) -> list[Event]:
    """Get ordered event timeline for a session."""
    return await ledger.get_timeline(session_id)


@router.get("/timeline/summary", response_model=TimelineSummary)
async def get_timeline_summary(
    ledger: LedgerDep,
    session_id: str = Query(...),
) -> TimelineSummary:
    """Get summary statistics for a session."""
    summary = await ledger.get_timeline_summary(session_id)
    if not summary:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    return summary


@router.get("/sessions", response_model=list[str])
async def list_sessions(ledger: LedgerDep) -> list[str]:
    """List all active session IDs."""
    return await ledger.list_sessions()


@router.get("/stats", response_model=dict)
async def get_stats(ledger: LedgerDep) -> dict:
    """Get overall statistics across all sessions."""
    return await ledger.get_stats()


@router.post("/events/search", response_model=list[Event])
async def search_events(
    ledger: LedgerDep,
    body: dict[str, Any],
) -> list[Event]:
    """
    Search events by text query.

    In Phase 1: falls back to listing all events (full-text search via pgvector in Phase 2).
    """
    # Phase 1: simple filter by decision or risk
    decision_filter = body.get("decision")
    min_risk = body.get("min_risk")
    limit = body.get("limit", 50)

    return await ledger.list_events(
        decision=Decision(decision_filter) if decision_filter else None,
        min_risk=min_risk,
        limit=limit,
    )
