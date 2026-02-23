"""SQLAlchemy async models for PostgreSQL + pgvector event storage."""

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
    String,
    Text,
    select,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

import structlog

from agentguard.core.models import (
    Action,
    ActionType,
    Decision,
    Event,
    PolicyViolation,
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

    event_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id = Column(String(64), nullable=False, index=True)
    agent_goal = Column(Text, nullable=False)
    framework = Column(String(64), nullable=False, default="unknown")

    # Action fields
    action_id = Column(String(64), nullable=False)
    action_type = Column(String(32), nullable=False, index=True)
    tool_name = Column(String(256), nullable=False)
    parameters = Column(JSONB, nullable=False, default=dict)
    raw_payload = Column(JSONB, nullable=False, default=dict)

    # Risk assessment
    risk_score = Column(Float, nullable=False, index=True)
    reason = Column(Text, nullable=False)
    indicators = Column(JSONB, nullable=False, default=list)
    is_goal_aligned = Column(Boolean, nullable=False, default=True)
    analyzer_model = Column(String(64), nullable=False, default="unknown")
    latency_ms = Column(Float, nullable=False, default=0.0)

    # Decision
    decision = Column(String(16), nullable=False, index=True)
    policy_rule = Column(String(128), nullable=True)
    policy_detail = Column(Text, nullable=True)

    # Metadata
    provenance = Column(JSONB, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, index=True)

    # Vector embedding for semantic search (pgvector)
    # reason_embedding = Column(Vector(1536), nullable=True)  # Uncomment when pgvector enabled

    __table_args__ = (
        Index("ix_events_session_decision", "session_id", "decision"),
        Index("ix_events_risk_score_decision", "risk_score", "decision"),
        Index("ix_events_created_at_desc", "created_at"),
    )


class PostgresEventLedger(EventLedger):
    """
    PostgreSQL-backed event ledger using SQLAlchemy async.

    Phase 2 replacement for InMemoryEventLedger — no other code changes required.
    Implements the full EventLedger ABC.
    """

    def __init__(self, database_url: str) -> None:
        self._engine = create_async_engine(
            database_url,
            echo=False,
            pool_size=10,
            max_overflow=20,
            pool_timeout=30,
        )
        self._sessionmaker = async_sessionmaker(
            self._engine, class_=AsyncSession, expire_on_commit=False
        )

    async def create_tables(self) -> None:
        """Create all tables (use Alembic for production migrations)."""
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def close(self) -> None:
        await self._engine.dispose()

    # ------------------------------------------------------------------ #
    # EventLedger ABC implementation                                       #
    # ------------------------------------------------------------------ #

    async def append(self, event: Event) -> None:
        record = EventRecord(
            event_id=uuid.UUID(event.event_id),
            session_id=event.session_id,
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
            provenance=event.provenance,
            created_at=event.timestamp,
        )

        async with self._sessionmaker() as session:
            session.add(record)
            # Upsert session record
            existing = await session.get(SessionRecord, event.session_id)
            if existing is None:
                session.add(SessionRecord(
                    session_id=event.session_id,
                    agent_goal=event.agent_goal,
                    framework=event.framework,
                    created_at=event.timestamp,
                    updated_at=event.timestamp,
                    total_events=1,
                    blocked_events=1 if event.decision == Decision.BLOCK else 0,
                ))
            else:
                existing.updated_at = event.timestamp
                existing.total_events = (existing.total_events or 0) + 1
                if event.decision == Decision.BLOCK:
                    existing.blocked_events = (existing.blocked_events or 0) + 1
            await session.commit()

        logger.debug("event_persisted_postgres", event_id=str(event.event_id))

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
        query = select(EventRecord.session_id).distinct()
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
        """Get overall statistics across all sessions."""
        async with self._sessionmaker() as session:
            total = await session.scalar(select(func.count(EventRecord.event_id)))
            if not total:
                return {
                    "total_events": 0,
                    "blocked_events": 0,
                    "reviewed_events": 0,
                    "allowed_events": 0,
                    "active_sessions": 0,
                    "avg_risk_score": 0.0,
                }
            blocked = await session.scalar(
                select(func.count(EventRecord.event_id)).where(EventRecord.decision == "block")
            )
            reviewed = await session.scalar(
                select(func.count(EventRecord.event_id)).where(EventRecord.decision == "review")
            )
            allowed = await session.scalar(
                select(func.count(EventRecord.event_id)).where(EventRecord.decision == "allow")
            )
            sessions_count = await session.scalar(
                select(func.count(func.distinct(EventRecord.session_id)))
            )
            avg_risk = await session.scalar(select(func.avg(EventRecord.risk_score)))

        return {
            "total_events": total or 0,
            "blocked_events": blocked or 0,
            "reviewed_events": reviewed or 0,
            "allowed_events": allowed or 0,
            "active_sessions": sessions_count or 0,
            "avg_risk_score": float(avg_risk or 0.0),
        }

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _record_to_event(record: EventRecord) -> Event:
        """Reconstruct an Event Pydantic model from a database row."""
        policy_violation = None
        if record.policy_rule:
            policy_violation = PolicyViolation(
                rule_name=record.policy_rule,
                rule_type=record.policy_rule,
                detail=record.policy_detail or "",
                decision=Decision(record.decision),
            )

        return Event(
            event_id=str(record.event_id),
            session_id=record.session_id,
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
            ),
            decision=Decision(record.decision),
            policy_violation=policy_violation,
            provenance=record.provenance or {},
            timestamp=record.created_at,
        )
