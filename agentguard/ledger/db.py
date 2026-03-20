"""SQLAlchemy async models for PostgreSQL and SQLite event storage."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Index,
    Integer,
    JSON,
    String,
    Text,
    TypeDecorator,
    select,
    func,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase


class _FlexJSON(TypeDecorator):
    """Uses JSONB on PostgreSQL (indexed, efficient), plain JSON on SQLite."""
    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect: Any) -> Any:
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())


class _FlexUUID(TypeDecorator):
    """Uses native UUID on PostgreSQL, String(36) on SQLite."""
    impl = String(36)
    cache_ok = True

    def load_dialect_impl(self, dialect: Any) -> Any:
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        return dialect.type_descriptor(String(36))

    def process_bind_param(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        if dialect.name == "postgresql":
            if isinstance(value, uuid.UUID):
                return value
            return uuid.UUID(str(value))
        return str(value)

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))

import structlog

from sqlalchemy import text as sa_text

from agentguard.core.models import (
    Action,
    ActionType,
    AgentGraphData,
    AgentProfile,
    AttackTaxonomyAnnotation,
    Decision,
    Event,
    PolicyViolation,
    ProvenanceTag,
    RiskAssessment,
    TimelineSummary,
)
from agentguard.ledger.event_ledger import EventLedger

logger = structlog.get_logger(__name__)


class Base(DeclarativeBase):
    pass


class SessionRecord(Base):
    __tablename__ = "sessions"

    session_id = Column(String(64), primary_key=True)
    agent_goal = Column(Text, nullable=False)
    framework = Column(String(64), nullable=False, default="unknown")
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    total_events = Column(Integer, nullable=False, default=0)
    blocked_events = Column(Integer, nullable=False, default=0)


class EventRecord(Base):
    __tablename__ = "events"

    event_id = Column(_FlexUUID, primary_key=True, default=uuid.uuid4)
    session_id = Column(String(64), nullable=False)
    agent_id = Column(String(128), nullable=False, default="unknown")
    agent_is_registered = Column(Boolean, nullable=False, default=False)
    agent_goal = Column(Text, nullable=False)
    framework = Column(String(64), nullable=False, default="unknown")

    action_id = Column(String(64), nullable=False)
    action_type = Column(String(32), nullable=False)
    tool_name = Column(String(256), nullable=False)
    parameters = Column(_FlexJSON, nullable=False, default=dict)
    raw_payload = Column(_FlexJSON, nullable=False, default=dict)

    risk_score = Column(Float, nullable=False)
    reason = Column(Text, nullable=False)
    indicators = Column(_FlexJSON, nullable=False, default=list)
    is_goal_aligned = Column(Boolean, nullable=False, default=True)
    analyzer_model = Column(String(64), nullable=False, default="unknown")
    latency_ms = Column(Float, nullable=False, default=0.0)

    decision = Column(String(16), nullable=False)
    policy_rule = Column(String(128), nullable=True)
    policy_detail = Column(Text, nullable=True)
    policy_violation = Column(_FlexJSON, nullable=True)
    attack_taxonomy = Column(_FlexJSON, nullable=True)

    provenance = Column(_FlexJSON, nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("ix_events_session_id", "session_id"),
        Index("ix_events_agent_id", "agent_id"),
        Index("ix_events_decision", "decision"),
        Index("ix_events_risk_score", "risk_score"),
        Index("ix_events_created_at", "created_at"),
        Index("ix_events_action_type", "action_type"),
        Index("ix_events_session_decision", "session_id", "decision"),
    )


def _deserialize_provenance(raw: Any) -> list[ProvenanceTag]:
    """
    Convert JSONB provenance value to list[ProvenanceTag].

    Handles two formats:
    - New rows: list of tag dicts (e.g. [{"source_type": "system", "label": "..."}])
    - Legacy rows: empty dict {} or None (stored before Phase 7)
    """
    if isinstance(raw, list):
        return [ProvenanceTag.model_validate(t) for t in raw]
    return []


class PostgresEventLedger(EventLedger):
    """
    SQL-backed event ledger supporting PostgreSQL and SQLite.

    PostgreSQL (production):  DATABASE_URL=postgresql+asyncpg://...
    SQLite (local dev):       DATABASE_URL=sqlite+aiosqlite:///./agentguard.db
    """

    def __init__(self, database_url: str) -> None:
        self._is_sqlite = database_url.startswith("sqlite")
        if self._is_sqlite:
            # SQLite doesn't support connection pooling parameters
            self._engine = create_async_engine(database_url, echo=False)
        else:
            self._engine = create_async_engine(
                database_url,
                echo=False,
                pool_size=10,
                max_overflow=20,
                pool_timeout=30,
                pool_pre_ping=True,
                pool_recycle=3600,
            )
        self._sessionmaker = async_sessionmaker(
            self._engine, class_=AsyncSession, expire_on_commit=False
        )

    async def create_tables(self) -> None:
        """Create all tables if they don't exist. Used for SQLite local dev."""
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def close(self) -> None:
        await self._engine.dispose()

    async def append(self, event: Event) -> None:
        record = EventRecord(
            event_id=uuid.UUID(event.event_id),
            session_id=event.session_id,
            agent_id=event.agent_id,
            agent_is_registered=event.agent_is_registered,
            agent_goal=event.agent_goal,
            framework=event.framework,
            action_id=event.action.action_id,
            action_type=event.action.type.value,
            tool_name=event.action.tool_name,
            parameters=event.action.parameters,
            raw_payload=event.action.raw_payload,
            risk_score=event.assessment.risk_score,
            reason=event.assessment.reason,
            indicators=event.assessment.indicators,
            is_goal_aligned=bool(event.assessment.is_goal_aligned),
            analyzer_model=event.assessment.analyzer_model,
            latency_ms=event.assessment.latency_ms,
            decision=event.decision.value,
            policy_rule=event.policy_violation.rule_name if event.policy_violation else None,
            policy_detail=event.policy_violation.detail if event.policy_violation else None,
            policy_violation=event.policy_violation.model_dump() if event.policy_violation else None,
            provenance=[t.model_dump() for t in event.provenance],
            created_at=event.timestamp,
        )
        async with self._sessionmaker() as session:
            session.add(record)
            # Atomic upsert for the session row — eliminates the Python-level
            # read-then-write race when concurrent requests share a session_id.
            _insert = sqlite_insert if self._is_sqlite else pg_insert
            upsert_stmt = _insert(SessionRecord).values(
                session_id=event.session_id,
                agent_goal=event.agent_goal,
                framework=event.framework,
                created_at=event.timestamp,
                updated_at=event.timestamp,
                total_events=1,
                blocked_events=1 if event.decision == Decision.BLOCK else 0,
            ).on_conflict_do_update(
                index_elements=["session_id"],
                set_={
                    "updated_at": event.timestamp,
                    "total_events": SessionRecord.total_events + 1,
                    "blocked_events": SessionRecord.blocked_events + (
                        1 if event.decision == Decision.BLOCK else 0
                    ),
                },
            )
            await session.execute(upsert_stmt)
            await session.commit()
        logger.debug("event_persisted", event_id=str(event.event_id), agent_id=event.agent_id)

    async def get_event(self, event_id: str) -> Event | None:
        async with self._sessionmaker() as session:
            record = await session.get(EventRecord, uuid.UUID(event_id))
            return self._record_to_event(record) if record else None

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
        query = select(EventRecord)
        if session_id:
            query = query.where(EventRecord.session_id == session_id)
        if decision:
            query = query.where(EventRecord.decision == decision.value)
        if min_risk is not None:
            query = query.where(EventRecord.risk_score >= min_risk)
        if max_risk is not None:
            query = query.where(EventRecord.risk_score <= max_risk)
        if since:
            since_aware = since if since.tzinfo else since.replace(tzinfo=timezone.utc)
            query = query.where(EventRecord.created_at >= since_aware)
        if until:
            until_aware = until if until.tzinfo else until.replace(tzinfo=timezone.utc)
            query = query.where(EventRecord.created_at <= until_aware)
        query = query.order_by(EventRecord.created_at.desc()).offset(offset).limit(limit)
        async with self._sessionmaker() as session:
            result = await session.execute(query)
            return [self._record_to_event(r) for r in result.scalars()]

    async def get_timeline(self, session_id: str) -> list[Event]:
        query = (
            select(EventRecord)
            .where(EventRecord.session_id == session_id)
            .order_by(EventRecord.created_at.asc())
        )
        async with self._sessionmaker() as session:
            result = await session.execute(query)
            return [self._record_to_event(r) for r in result.scalars()]

    async def list_sessions(self) -> list[str]:
        # Order by most blocked events first so attack sessions appear at the top of the
        # timeline selector instead of alphabetically (which would surface baseline sessions first).
        query = (
            select(SessionRecord.session_id)
            .order_by(SessionRecord.blocked_events.desc(), SessionRecord.total_events.desc())
        )
        async with self._sessionmaker() as session:
            result = await session.execute(query)
            return [row[0] for row in result]

    async def get_timeline_summary(self, session_id: str) -> TimelineSummary | None:
        events = await self.get_timeline(session_id)
        if not events:
            return None
        blocked = [e for e in events if e.decision == Decision.BLOCK]
        reviewed = [e for e in events if e.decision == Decision.REVIEW]
        allowed = [e for e in events if e.decision == Decision.ALLOW]
        risk_scores = [e.assessment.risk_score for e in events]
        attack_vectors = list({ind for e in blocked for ind in e.assessment.indicators})
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
        async with self._sessionmaker() as session:
            total = await session.scalar(select(func.count(EventRecord.event_id)))
            if not total:
                return {"total_events": 0, "blocked_events": 0, "reviewed_events": 0,
                        "allowed_events": 0, "active_sessions": 0, "avg_risk_score": 0.0}
            blocked = await session.scalar(
                select(func.count(EventRecord.event_id)).where(EventRecord.decision == "block"))
            reviewed = await session.scalar(
                select(func.count(EventRecord.event_id)).where(EventRecord.decision == "review"))
            allowed = await session.scalar(
                select(func.count(EventRecord.event_id)).where(EventRecord.decision == "allow"))
            sessions_count = await session.scalar(
                select(func.count(func.distinct(EventRecord.session_id))))
            avg_risk = await session.scalar(select(func.avg(EventRecord.risk_score)))
        return {
            "total_events": total or 0,
            "blocked_events": blocked or 0,
            "reviewed_events": reviewed or 0,
            "allowed_events": allowed or 0,
            "active_sessions": sessions_count or 0,
            "avg_risk_score": float(avg_risk or 0.0),
        }

    async def list_agents(self) -> list[AgentProfile]:
        """List all distinct agents with aggregated profile data."""
        # Group only by agent_id so one agent never produces multiple rows.
        # agent_goal / framework use MAX() to pick a consistent representative
        # value; agent_is_registered uses BOOL_OR (true if any event was
        # from a registered agent). This handles the legacy-unknown backfill
        # where those fields may vary across events.
        query = (
            select(
                EventRecord.agent_id,
                func.max(EventRecord.agent_goal).label("agent_goal"),
                func.max(EventRecord.framework).label("framework"),
                func.bool_or(EventRecord.agent_is_registered).label("agent_is_registered"),
                func.min(EventRecord.created_at).label("first_seen"),
                func.max(EventRecord.created_at).label("last_seen"),
                func.count(func.distinct(EventRecord.session_id)).label("total_sessions"),
                func.count(EventRecord.event_id).label("total_events"),
                func.sum(func.cast(EventRecord.decision == "block", Integer)).label("blocked_events"),
                func.sum(func.cast(EventRecord.decision == "review", Integer)).label("reviewed_events"),
                func.sum(func.cast(EventRecord.decision == "allow", Integer)).label("allowed_events"),
                func.avg(EventRecord.risk_score).label("avg_risk"),
                func.max(EventRecord.risk_score).label("max_risk"),
            )
            .group_by(EventRecord.agent_id)
            .order_by(func.max(EventRecord.created_at).desc())
        )
        async with self._sessionmaker() as session:
            result = await session.execute(query)
            profiles = []
            for row in result:
                tools, patterns, trend = await self._agent_details(session, row.agent_id)
                profiles.append(AgentProfile(
                    agent_id=row.agent_id,
                    agent_goal=row.agent_goal,
                    is_registered=bool(row.agent_is_registered),
                    framework=row.framework,
                    first_seen=row.first_seen,
                    last_seen=row.last_seen,
                    total_sessions=row.total_sessions,
                    total_events=row.total_events,
                    blocked_events=row.blocked_events or 0,
                    reviewed_events=row.reviewed_events or 0,
                    allowed_events=row.allowed_events or 0,
                    avg_risk_score=float(row.avg_risk or 0.0),
                    max_risk_score=float(row.max_risk or 0.0),
                    attack_patterns=patterns,
                    tools_used=tools,
                    risk_trend=trend,
                ))
            return profiles

    async def get_agent_profile(self, agent_id: str) -> AgentProfile | None:
        """Get full profile for a single agent."""
        query = (
            select(
                EventRecord.agent_id,
                func.max(EventRecord.agent_goal).label("agent_goal"),
                func.max(EventRecord.framework).label("framework"),
                func.bool_or(EventRecord.agent_is_registered).label("agent_is_registered"),
                func.min(EventRecord.created_at).label("first_seen"),
                func.max(EventRecord.created_at).label("last_seen"),
                func.count(func.distinct(EventRecord.session_id)).label("total_sessions"),
                func.count(EventRecord.event_id).label("total_events"),
                func.sum(func.cast(EventRecord.decision == "block", Integer)).label("blocked_events"),
                func.sum(func.cast(EventRecord.decision == "review", Integer)).label("reviewed_events"),
                func.sum(func.cast(EventRecord.decision == "allow", Integer)).label("allowed_events"),
                func.avg(EventRecord.risk_score).label("avg_risk"),
                func.max(EventRecord.risk_score).label("max_risk"),
            )
            .where(EventRecord.agent_id == agent_id)
            .group_by(EventRecord.agent_id)
        )
        async with self._sessionmaker() as session:
            result = await session.execute(query)
            row = result.first()
            if not row:
                return None
            tools, patterns, trend = await self._agent_details(session, agent_id)
            return AgentProfile(
                agent_id=row.agent_id,
                agent_goal=row.agent_goal,
                is_registered=bool(row.agent_is_registered),
                framework=row.framework,
                first_seen=row.first_seen,
                last_seen=row.last_seen,
                total_sessions=row.total_sessions,
                total_events=row.total_events,
                blocked_events=row.blocked_events or 0,
                reviewed_events=row.reviewed_events or 0,
                allowed_events=row.allowed_events or 0,
                avg_risk_score=float(row.avg_risk or 0.0),
                max_risk_score=float(row.max_risk or 0.0),
                attack_patterns=patterns,
                tools_used=tools,
                risk_trend=trend,
            )

    async def get_agent_graph(self, agent_id: str) -> AgentGraphData:
        """Build graph nodes and edges for the knowledge graph visualization."""
        query = (
            select(EventRecord)
            .where(EventRecord.agent_id == agent_id)
            .order_by(EventRecord.created_at.asc())
            .limit(500)
        )
        async with self._sessionmaker() as session:
            result = await session.execute(query)
            agent_events = [self._record_to_event(r) for r in result.scalars()]
        if not agent_events:
            return AgentGraphData(nodes=[], edges=[])

        nodes: dict[str, dict] = {}
        edges: list[dict] = []
        profile = await self.get_agent_profile(agent_id)

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

        for event in agent_events:
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

    async def update_event_taxonomy(
        self,
        event_id: str,
        annotation: AttackTaxonomyAnnotation,
    ) -> None:
        """Attach a post-hoc taxonomy annotation to an existing event."""
        stmt = sa_text(
            "UPDATE events SET attack_taxonomy = :annotation::jsonb WHERE event_id = :event_id"
        )
        async with self._sessionmaker() as session:
            await session.execute(
                stmt,
                {"annotation": annotation.model_dump_json(), "event_id": event_id},
            )
            await session.commit()

    async def search_events_fulltext(self, query: str, limit: int = 20) -> list[Event]:
        """Return events whose reason field contains the query string (case-insensitive)."""
        async with self._sessionmaker() as session:
            result = await session.execute(
                select(EventRecord)
                .where(EventRecord.reason.ilike(f"%{query}%"))
                .order_by(EventRecord.created_at.desc())
                .limit(limit)
            )
            records = result.scalars().all()
        return [self._record_to_event(r) for r in records]

    async def _agent_details(
        self, session: AsyncSession, agent_id: str
    ) -> tuple[list[str], list[str], list[float]]:
        """Return (tools_used, attack_patterns, risk_trend) for an agent."""
        result = await session.execute(
            select(EventRecord.tool_name, EventRecord.indicators, EventRecord.risk_score)
            .where(EventRecord.agent_id == agent_id)
            .order_by(EventRecord.created_at.desc())
            .limit(100)
        )
        rows = result.all()
        tools = list(dict.fromkeys(r.tool_name for r in rows))[:20]
        patterns: list[str] = []
        for r in rows:
            for ind in (r.indicators or []):
                if ind not in patterns:
                    patterns.append(ind)
        risk_trend = [r.risk_score for r in reversed(rows)][-20:]
        return tools, patterns[:10], risk_trend

    @staticmethod
    def _record_to_event(record: EventRecord) -> Event:
        # Prefer the full JSONB snapshot (Phase 8+); fall back to legacy columns
        if record.policy_violation:
            policy_violation = PolicyViolation.model_validate(record.policy_violation)
        elif record.policy_rule:
            policy_violation = PolicyViolation(
                rule_name=record.policy_rule,
                rule_type=record.policy_rule,
                detail=record.policy_detail or "",
                decision=Decision(record.decision),
            )
        else:
            policy_violation = None

        attack_taxonomy = (
            AttackTaxonomyAnnotation.model_validate(record.attack_taxonomy)
            if record.attack_taxonomy
            else None
        )

        return Event(
            event_id=str(record.event_id),
            session_id=record.session_id,
            agent_id=record.agent_id,
            agent_is_registered=bool(record.agent_is_registered),
            agent_goal=record.agent_goal,
            framework=record.framework,
            action=Action(
                action_id=record.action_id,
                type=ActionType(record.action_type),
                tool_name=record.tool_name,
                parameters=record.parameters or {},
                raw_payload=record.raw_payload or {},
            ),
            assessment=RiskAssessment(
                risk_score=record.risk_score,
                reason=record.reason,
                indicators=record.indicators or [],
                is_goal_aligned=bool(record.is_goal_aligned),
                analyzer_model=record.analyzer_model,
                latency_ms=record.latency_ms,
                attack_taxonomy=attack_taxonomy,
            ),
            decision=Decision(record.decision),
            policy_violation=policy_violation,
            provenance=_deserialize_provenance(record.provenance),
            timestamp=record.created_at,
        )
