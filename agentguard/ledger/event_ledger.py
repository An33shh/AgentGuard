"""Event ledger: InMemoryEventLedger (Phase 1) + PostgresEventLedger (Phase 2)."""

from __future__ import annotations

import abc
import asyncio
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

import structlog

from agentguard.core.models import AgentGraphData, AgentProfile, Decision, Event, TimelineSummary, derive_agent_id

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

    @abc.abstractmethod
    async def list_agents(self) -> list[AgentProfile]:
        """List all distinct agents with aggregated profile data."""

    @abc.abstractmethod
    async def get_agent_profile(self, agent_id: str) -> AgentProfile | None:
        """Get full profile for a single agent."""

    @abc.abstractmethod
    async def get_agent_graph(self, agent_id: str) -> AgentGraphData:
        """Get graph nodes and edges for the knowledge graph visualization."""


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

    async def list_agents(self) -> list[AgentProfile]:
        events = list(self._events.values())
        agents: dict[str, list[Event]] = {}
        for e in events:
            agents.setdefault(e.agent_id, []).append(e)
        profiles = []
        for agent_id, evts in agents.items():
            evts_sorted = sorted(evts, key=lambda e: e.timestamp)
            risk_scores = [e.assessment.risk_score for e in evts_sorted]
            blocked = [e for e in evts if e.decision == Decision.BLOCK]
            patterns = list(dict.fromkeys(ind for e in blocked for ind in e.assessment.indicators))
            tools = list(dict.fromkeys(e.action.tool_name for e in evts_sorted))
            profiles.append(AgentProfile(
                agent_id=agent_id,
                agent_goal=evts_sorted[0].agent_goal,
                is_registered=evts_sorted[-1].agent_is_registered,
                framework=evts_sorted[0].framework,
                first_seen=evts_sorted[0].timestamp,
                last_seen=evts_sorted[-1].timestamp,
                total_sessions=len({e.session_id for e in evts}),
                total_events=len(evts),
                blocked_events=len(blocked),
                reviewed_events=sum(1 for e in evts if e.decision == Decision.REVIEW),
                allowed_events=sum(1 for e in evts if e.decision == Decision.ALLOW),
                avg_risk_score=sum(risk_scores) / len(risk_scores),
                max_risk_score=max(risk_scores),
                attack_patterns=patterns[:10],
                tools_used=tools[:20],
                risk_trend=risk_scores[-20:],
            ))
        return sorted(profiles, key=lambda p: p.last_seen, reverse=True)

    async def get_agent_profile(self, agent_id: str) -> AgentProfile | None:
        profiles = await self.list_agents()
        return next((p for p in profiles if p.agent_id == agent_id), None)

    async def get_agent_graph(self, agent_id: str) -> AgentGraphData:
        agent_events = [e for e in self._events.values() if e.agent_id == agent_id]
        if not agent_events:
            return AgentGraphData(nodes=[], edges=[])

        profile = await self.get_agent_profile(agent_id)
        nodes: dict[str, dict] = {}
        edges: list[dict] = []

        agent_node_id = f"agent:{agent_id}"
        nodes[agent_node_id] = {
            "id": agent_node_id, "type": "agent",
            "label": (profile.agent_goal[:40] if profile else agent_id),
            "agent_id": agent_id,
            "is_registered": profile.is_registered if profile else False,
            "total_events": profile.total_events if profile else 0,
            "avg_risk": profile.avg_risk_score if profile else 0.0,
        }

        sessions_seen: set[str] = set()
        tools_seen: set[str] = set()
        patterns_seen: set[str] = set()

        for event in sorted(agent_events, key=lambda e: e.timestamp):
            session_node_id = f"session:{event.session_id}"
            if event.session_id not in sessions_seen:
                sessions_seen.add(event.session_id)
                nodes[session_node_id] = {
                    "id": session_node_id, "type": "session",
                    "label": event.session_id[:16],
                    "session_id": event.session_id,
                    "timestamp": event.timestamp.isoformat(),
                }
                edges.append({"source": agent_node_id, "target": session_node_id, "type": "had_session"})

            tool_node_id = f"tool:{event.action.tool_name}"
            if event.action.tool_name not in tools_seen:
                tools_seen.add(event.action.tool_name)
                nodes[tool_node_id] = {
                    "id": tool_node_id, "type": "tool",
                    "label": event.action.tool_name,
                    "decision": event.decision.value,
                }
            edges.append({
                "source": session_node_id, "target": tool_node_id,
                "type": "used_tool", "decision": event.decision.value,
                "risk_score": event.assessment.risk_score,
            })

            for indicator in event.assessment.indicators:
                pattern_node_id = f"pattern:{indicator}"
                if indicator not in patterns_seen:
                    patterns_seen.add(indicator)
                    nodes[pattern_node_id] = {
                        "id": pattern_node_id, "type": "pattern",
                        "label": indicator.replace("_", " ").title(),
                        "indicator": indicator,
                    }
                edges.append({"source": tool_node_id, "target": pattern_node_id, "type": "exhibited_pattern"})

        return AgentGraphData(nodes=list(nodes.values()), edges=edges)

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
