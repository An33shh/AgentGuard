"""SQLite integration tests for PostgresEventLedger.

These tests exercise the SQL ledger against SQLite to catch dialect-specific
issues (e.g. ::jsonb casts, bool_or aggregates) that would only surface in
production on PostgreSQL if not tested locally.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from agentguard.core.models import (
    Action,
    ActionType,
    AttackTaxonomyAnnotation,
    Decision,
    Event,
    RiskAssessment,
)
from agentguard.ledger.db import PostgresEventLedger


@pytest.fixture
async def sqlite_ledger(tmp_path):
    db_path = tmp_path / "test.db"
    ledger = PostgresEventLedger(f"sqlite+aiosqlite:///{db_path}")
    await ledger.create_tables()
    yield ledger
    await ledger.close()


def _make_event(
    session_id: str = "sess-001",
    agent_id: str = "agent-test",
    agent_goal: str = "test goal",
    decision: Decision = Decision.ALLOW,
    tool_name: str = "file.read",
    risk_score: float = 0.1,
    is_registered: bool = True,
) -> Event:
    return Event(
        event_id=str(uuid.uuid4()),
        session_id=session_id,
        agent_id=agent_id,
        agent_is_registered=is_registered,
        agent_goal=agent_goal,
        framework="test",
        action=Action(
            action_id=str(uuid.uuid4()),
            type=ActionType.TOOL_CALL,
            tool_name=tool_name,
            parameters={"path": "/tmp/test.txt"},
            raw_payload={"tool_name": tool_name},
        ),
        assessment=RiskAssessment(
            risk_score=risk_score,
            reason="test assessment",
            indicators=[],
            is_goal_aligned=True,
            analyzer_model="test",
            latency_ms=5.0,
        ),
        decision=decision,
        correlation_id=str(uuid.uuid4()),
        initiating_principal="test-principal",
        timestamp=datetime.now(timezone.utc),
    )


class TestSQLiteBasicOperations:
    @pytest.mark.asyncio
    async def test_append_and_get_event(self, sqlite_ledger: PostgresEventLedger) -> None:
        event = _make_event()
        await sqlite_ledger.append(event)
        retrieved = await sqlite_ledger.get_event(event.event_id)
        assert retrieved is not None
        assert retrieved.event_id == event.event_id
        assert retrieved.session_id == event.session_id

    @pytest.mark.asyncio
    async def test_correlation_id_persisted(self, sqlite_ledger: PostgresEventLedger) -> None:
        event = _make_event()
        await sqlite_ledger.append(event)
        retrieved = await sqlite_ledger.get_event(event.event_id)
        assert retrieved.correlation_id == event.correlation_id

    @pytest.mark.asyncio
    async def test_initiating_principal_persisted(self, sqlite_ledger: PostgresEventLedger) -> None:
        event = _make_event()
        await sqlite_ledger.append(event)
        retrieved = await sqlite_ledger.get_event(event.event_id)
        assert retrieved.initiating_principal == "test-principal"

    @pytest.mark.asyncio
    async def test_list_events(self, sqlite_ledger: PostgresEventLedger) -> None:
        for i in range(3):
            await sqlite_ledger.append(_make_event(session_id=f"sess-{i}"))
        events = await sqlite_ledger.list_events(limit=10)
        assert len(events) == 3

    @pytest.mark.asyncio
    async def test_list_events_filter_decision(self, sqlite_ledger: PostgresEventLedger) -> None:
        await sqlite_ledger.append(_make_event(decision=Decision.BLOCK))
        await sqlite_ledger.append(_make_event(decision=Decision.ALLOW))
        blocked = await sqlite_ledger.list_events(decision=Decision.BLOCK)
        assert len(blocked) == 1
        assert blocked[0].decision == Decision.BLOCK

    @pytest.mark.asyncio
    async def test_list_sessions(self, sqlite_ledger: PostgresEventLedger) -> None:
        await sqlite_ledger.append(_make_event(session_id="sess-a"))
        await sqlite_ledger.append(_make_event(session_id="sess-b"))
        sessions = await sqlite_ledger.list_sessions()
        assert set(sessions) == {"sess-a", "sess-b"}

    @pytest.mark.asyncio
    async def test_get_stats(self, sqlite_ledger: PostgresEventLedger) -> None:
        await sqlite_ledger.append(_make_event(decision=Decision.ALLOW))
        await sqlite_ledger.append(_make_event(decision=Decision.BLOCK))
        stats = await sqlite_ledger.get_stats()
        assert stats["total_events"] == 2
        assert stats["blocked_events"] == 1
        assert stats["allowed_events"] == 1


class TestSQLiteAgentProfile:
    @pytest.mark.asyncio
    async def test_list_agents_no_bool_or_crash(self, sqlite_ledger: PostgresEventLedger) -> None:
        """list_agents must not crash on SQLite (no bool_or aggregate)."""
        await sqlite_ledger.append(_make_event(agent_id="agent-x", is_registered=True))
        await sqlite_ledger.append(_make_event(agent_id="agent-x", is_registered=False))
        profiles = await sqlite_ledger.list_agents()
        assert len(profiles) == 1
        assert profiles[0].is_registered is True  # max(cast(bool, int)) → 1 → True

    @pytest.mark.asyncio
    async def test_get_agent_profile_no_bool_or_crash(self, sqlite_ledger: PostgresEventLedger) -> None:
        """get_agent_profile must not crash on SQLite."""
        await sqlite_ledger.append(_make_event(agent_id="agent-y", decision=Decision.BLOCK, risk_score=0.9))
        await sqlite_ledger.append(_make_event(agent_id="agent-y", decision=Decision.ALLOW, risk_score=0.1))
        profile = await sqlite_ledger.get_agent_profile("agent-y")
        assert profile is not None
        assert profile.blocked_events == 1
        assert profile.allowed_events == 1

    @pytest.mark.asyncio
    async def test_agent_profile_case_aggregation(self, sqlite_ledger: PostgresEventLedger) -> None:
        """Verify portable case() aggregation produces correct counts."""
        for _ in range(3):
            await sqlite_ledger.append(_make_event(agent_id="agent-z", decision=Decision.BLOCK))
        for _ in range(2):
            await sqlite_ledger.append(_make_event(agent_id="agent-z", decision=Decision.ALLOW))
        profile = await sqlite_ledger.get_agent_profile("agent-z")
        assert profile.blocked_events == 3
        assert profile.allowed_events == 2
        assert profile.total_events == 5


class TestSQLiteTaxonomy:
    @pytest.mark.asyncio
    async def test_update_event_taxonomy_no_jsonb_crash(self, sqlite_ledger: PostgresEventLedger) -> None:
        """update_event_taxonomy must not use ::jsonb cast on SQLite."""
        event = _make_event()
        await sqlite_ledger.append(event)
        annotation = AttackTaxonomyAnnotation(
            attack_pattern="credential_exfiltration",
            mitre_atlas_ids=["AML.T0058"],
            owasp_categories=["AA03"],
            confidence=0.85,
        )
        # Should not raise on SQLite
        await sqlite_ledger.update_event_taxonomy(event.event_id, annotation)
        retrieved = await sqlite_ledger.get_event(event.event_id)
        assert retrieved is not None
