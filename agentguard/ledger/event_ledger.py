"""Event ledger: InMemoryEventLedger (Phase 1) + PostgresEventLedger (Phase 2)."""

from __future__ import annotations

import abc
import asyncio
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

import structlog

from agentguard.core.models import Decision, Event, TimelineSummary

logger = structlog.get_logger(__name__)


class EventLedger(abc.ABC):
    """Abstract base class for event ledgers."""

    @abc.abstractmethod
    async def append(self, event: Event) -> None:
        """Persist a new event."""

    @abc.abstractmethod
    async def get_event(self, event_id: str) -> Event | None:
        """Retrieve a single event by ID."""

    @abc.abstractmethod
    async def list_events(
        self,
        session_id: str | None = None,
        decision: Decision | None = None,
        min_risk: float | None = None,
        max_risk: float | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Event]:
        """List events with optional filters."""

    @abc.abstractmethod
    async def get_timeline(self, session_id: str) -> list[Event]:
        """Get ordered timeline for a session."""

    @abc.abstractmethod
    async def list_sessions(self) -> list[str]:
        """List all session IDs."""

    @abc.abstractmethod
    async def get_timeline_summary(self, session_id: str) -> TimelineSummary | None:
        """Get summary statistics for a session."""

    @abc.abstractmethod
    async def get_stats(self) -> dict[str, Any]:
        """Get overall statistics across all sessions."""


class InMemoryEventLedger(EventLedger):
    """
    In-memory event ledger for Phase 1 (no database required).

    Async-safe via asyncio.Lock. Swapped for PostgresEventLedger in Phase 2
    with no other code changes needed.
    """

    def __init__(self) -> None:
        self._events: dict[str, Event] = {}
        self._sessions: dict[str, list[str]] = defaultdict(list)  # session_id → [event_id]
        self._lock = asyncio.Lock()

    async def append(self, event: Event) -> None:
        async with self._lock:
            self._events[event.event_id] = event
            self._sessions[event.session_id].append(event.event_id)
        logger.debug("event_appended", event_id=event.event_id, session_id=event.session_id)

    async def get_event(self, event_id: str) -> Event | None:
        return self._events.get(event_id)

    async def list_events(
        self,
        session_id: str | None = None,
        decision: Decision | None = None,
        min_risk: float | None = None,
        max_risk: float | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Event]:
        events = list(self._events.values())

        if session_id:
            events = [e for e in events if e.session_id == session_id]
        if decision:
            events = [e for e in events if e.decision == decision]
        if min_risk is not None:
            events = [e for e in events if e.assessment.risk_score >= min_risk]
        if max_risk is not None:
            events = [e for e in events if e.assessment.risk_score <= max_risk]
        if since:
            since_aware = since if since.tzinfo else since.replace(tzinfo=timezone.utc)
            events = [e for e in events if e.timestamp >= since_aware]
        if until:
            until_aware = until if until.tzinfo else until.replace(tzinfo=timezone.utc)
            events = [e for e in events if e.timestamp <= until_aware]

        events.sort(key=lambda e: e.timestamp, reverse=True)
        return events[offset : offset + limit]

    async def get_timeline(self, session_id: str) -> list[Event]:
        event_ids = self._sessions.get(session_id, [])
        events = [self._events[eid] for eid in event_ids if eid in self._events]
        events.sort(key=lambda e: e.timestamp)
        return events

    async def list_sessions(self) -> list[str]:
        return list(self._sessions.keys())

    async def get_timeline_summary(self, session_id: str) -> TimelineSummary | None:
        events = await self.get_timeline(session_id)
        if not events:
            return None

        blocked = [e for e in events if e.decision == Decision.BLOCK]
        reviewed = [e for e in events if e.decision == Decision.REVIEW]
        allowed = [e for e in events if e.decision == Decision.ALLOW]
        risk_scores = [e.assessment.risk_score for e in events]
        attack_vectors = list({
            ind for e in blocked for ind in e.assessment.indicators
        })

        return TimelineSummary(
            session_id=session_id,
            total_events=len(events),
            blocked_events=len(blocked),
            reviewed_events=len(reviewed),
            allowed_events=len(allowed),
            max_risk_score=max(risk_scores),
            avg_risk_score=sum(risk_scores) / len(risk_scores),
            start_time=events[0].timestamp,
            end_time=events[-1].timestamp,
            attack_vectors=attack_vectors,
        )

    async def get_stats(self) -> dict[str, Any]:
        """Get overall statistics across all sessions."""
        events = list(self._events.values())
        if not events:
            return {
                "total_events": 0,
                "blocked_events": 0,
                "reviewed_events": 0,
                "allowed_events": 0,
                "active_sessions": 0,
                "avg_risk_score": 0.0,
            }
        return {
            "total_events": len(events),
            "blocked_events": sum(1 for e in events if e.decision == Decision.BLOCK),
            "reviewed_events": sum(1 for e in events if e.decision == Decision.REVIEW),
            "allowed_events": sum(1 for e in events if e.decision == Decision.ALLOW),
            "active_sessions": len(self._sessions),
            "avg_risk_score": sum(e.assessment.risk_score for e in events) / len(events),
        }
