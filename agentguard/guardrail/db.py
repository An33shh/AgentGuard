"""SQLAlchemy async storage for GuardrailLedger.

PostgreSQL (production):  AGENTGUARD_GUARDRAIL_DB_URL=postgresql+asyncpg://...
SQLite (local dev):       AGENTGUARD_GUARDRAIL_DB_URL=sqlite+aiosqlite:///./guardrail.db

Falls back to DATABASE_URL if AGENTGUARD_GUARDRAIL_DB_URL is not set,
so a single DB_URL env var covers both ledgers.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Index,
    Integer,
    JSON,
    String,
    TypeDecorator,
    select,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

import structlog

from agentguard.guardrail.ledger import GuardrailLedger
from agentguard.guardrail.models import (
    ContextType,
    DetectionCategory,
    GuardrailDetection,
    GuardrailEvent,
    GuardrailMode,
    GuardrailResult,
    GuardrailVerdict,
)

logger = structlog.get_logger(__name__)


class _FlexJSON(TypeDecorator):
    """JSONB on PostgreSQL, plain JSON on SQLite."""
    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect: Any) -> Any:
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())


class GuardrailBase(DeclarativeBase):
    pass


class GuardrailEventRecord(GuardrailBase):
    __tablename__ = "guardrail_events"

    event_id = Column(String(64), primary_key=True)
    session_id = Column(String(64), nullable=False, index=True)
    agent_id = Column(String(128), nullable=False, default="")

    # GuardrailResult fields (flattened for queryability)
    scan_id = Column(String(64), nullable=False)
    verdict = Column(String(16), nullable=False, index=True)
    context_type = Column(String(32), nullable=False)
    mode = Column(String(16), nullable=False)
    analyzer_model = Column(String(64), nullable=False, default="local_scanner")
    latency_ms = Column(Float, nullable=False, default=0.0)
    detections = Column(_FlexJSON, nullable=False, default=list)

    # Never store raw text — only hash and length
    text_hash = Column(String(64), nullable=False)
    text_length = Column(Integer, nullable=False, default=0)

    created_at = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("ix_guardrail_session_verdict", "session_id", "verdict"),
        Index("ix_guardrail_created_at", "created_at"),
        Index("ix_guardrail_text_hash", "text_hash"),
    )


class PostgresGuardrailLedger(GuardrailLedger):
    """
    SQL-backed GuardrailLedger.

    Shares connection pool config with PostgresEventLedger.
    Guardrail events are stored in a separate table (guardrail_events)
    so the schema stays decoupled from the main events table.
    """

    def __init__(self, database_url: str) -> None:
        self._is_sqlite = database_url.startswith("sqlite")
        if self._is_sqlite:
            self._engine = create_async_engine(database_url, echo=False)
        else:
            self._engine = create_async_engine(
                database_url,
                echo=False,
                pool_size=5,
                max_overflow=10,
                pool_timeout=30,
                pool_pre_ping=True,
                pool_recycle=3600,
            )
        self._sessionmaker = async_sessionmaker(
            self._engine, class_=AsyncSession, expire_on_commit=False
        )

    async def create_tables(self) -> None:
        """Create guardrail_events table if it doesn't exist."""
        async with self._engine.begin() as conn:
            await conn.run_sync(GuardrailBase.metadata.create_all)

    async def close(self) -> None:
        await self._engine.dispose()

    async def append_guardrail_event(self, event: GuardrailEvent) -> None:
        record = GuardrailEventRecord(
            event_id=event.event_id,
            session_id=event.session_id,
            agent_id=event.agent_id,
            scan_id=event.result.scan_id,
            verdict=event.result.verdict.value,
            context_type=event.result.context_type.value,
            mode=event.result.mode.value,
            analyzer_model=event.result.analyzer_model,
            latency_ms=event.result.latency_ms,
            detections=[d.model_dump() for d in event.result.detections],
            text_hash=event.text_hash,
            text_length=event.text_length,
            created_at=event.timestamp,
        )
        async with self._sessionmaker() as session:
            session.add(record)
            await session.commit()
        logger.debug(
            "guardrail_event_persisted",
            event_id=event.event_id,
            verdict=event.result.verdict.value,
            session_id=event.session_id,
        )

    async def list_guardrail_events(
        self,
        session_id: str | None = None,
        verdict: GuardrailVerdict | None = None,
        limit: int = 100,
    ) -> list[GuardrailEvent]:
        query = select(GuardrailEventRecord)
        if session_id is not None:
            query = query.where(GuardrailEventRecord.session_id == session_id)
        if verdict is not None:
            query = query.where(GuardrailEventRecord.verdict == verdict.value)
        query = query.order_by(GuardrailEventRecord.created_at.desc()).limit(limit)

        async with self._sessionmaker() as session:
            result = await session.execute(query)
            return [self._record_to_event(r) for r in result.scalars()]

    async def get_stats(self) -> dict[str, Any]:
        """Aggregate guardrail scan statistics."""
        async with self._sessionmaker() as session:
            total = await session.scalar(
                select(func.count(GuardrailEventRecord.event_id))
            )
            if not total:
                return {"total_scans": 0, "blocked": 0, "redacted": 0, "allowed": 0}
            from sqlalchemy import case
            result = await session.execute(
                select(
                    func.sum(case((GuardrailEventRecord.verdict == "block", 1), else_=0)).label("blocked"),
                    func.sum(case((GuardrailEventRecord.verdict == "redact", 1), else_=0)).label("redacted"),
                    func.sum(case((GuardrailEventRecord.verdict == "allow", 1), else_=0)).label("allowed"),
                )
            )
            row = result.first()
        return {
            "total_scans": total,
            "blocked": row.blocked or 0,
            "redacted": row.redacted or 0,
            "allowed": row.allowed or 0,
        }

    @staticmethod
    def _record_to_event(record: GuardrailEventRecord) -> GuardrailEvent:
        detections = [
            GuardrailDetection(
                category=DetectionCategory(d["category"]),
                pattern_name=d["pattern_name"],
                matched_snippet=d["matched_snippet"],
                start_offset=d["start_offset"],
                end_offset=d["end_offset"],
                confidence=d["confidence"],
            )
            for d in (record.detections or [])
        ]
        result = GuardrailResult(
            scan_id=record.scan_id,
            verdict=GuardrailVerdict(record.verdict),
            context_type=ContextType(record.context_type),
            mode=GuardrailMode(record.mode),
            detections=detections,
            redacted_text=None,  # Never persisted — only stored at scan time
            analyzer_model=record.analyzer_model,
            latency_ms=record.latency_ms,
            timestamp=record.created_at,
        )
        return GuardrailEvent(
            event_id=record.event_id,
            session_id=record.session_id,
            agent_id=record.agent_id,
            result=result,
            text_hash=record.text_hash,
            text_length=record.text_length,
            timestamp=record.created_at,
        )
