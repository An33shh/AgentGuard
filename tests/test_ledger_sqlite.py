"""SQLite integration tests for PostgresEventLedger.

These tests exercise the SQL ledger against SQLite to catch dialect-specific
issues (e.g. ::jsonb casts, bool_or aggregates) that would only surface in
production on PostgreSQL if not tested locally.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

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
    reason: str = "test assessment",
    indicators: list[str] | None = None,
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
            reason=reason,
            indicators=indicators if indicators is not None else [],
            is_goal_aligned=True,
            analyzer_model="test",
            latency_ms=5.0,
        ),
        decision=decision,
        correlation_id=str(uuid.uuid4()),
        initiating_principal="test-principal",
        timestamp=datetime.now(UTC),
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
    async def test_list_events_filter_agent_id(self, sqlite_ledger: PostgresEventLedger) -> None:
        await sqlite_ledger.append(_make_event(agent_id="agent-a"))
        await sqlite_ledger.append(_make_event(agent_id="agent-a"))
        await sqlite_ledger.append(_make_event(agent_id="agent-b"))
        events = await sqlite_ledger.list_events(agent_id="agent-a")
        assert len(events) == 2
        assert all(e.agent_id == "agent-a" for e in events)

    @pytest.mark.asyncio
    async def test_search_events_fulltext_composes_with_filters(
        self, sqlite_ledger: PostgresEventLedger
    ) -> None:
        await sqlite_ledger.append(_make_event(agent_id="agent-a", decision=Decision.BLOCK, reason="suspicious exfil attempt"))
        await sqlite_ledger.append(_make_event(agent_id="agent-a", decision=Decision.ALLOW, reason="suspicious exfil attempt"))
        await sqlite_ledger.append(_make_event(agent_id="agent-b", decision=Decision.BLOCK, reason="suspicious exfil attempt"))
        await sqlite_ledger.append(_make_event(agent_id="agent-a", decision=Decision.BLOCK, reason="unrelated benign action"))

        results = await sqlite_ledger.search_events_fulltext("exfil", decision=Decision.BLOCK, agent_id="agent-a")
        assert len(results) == 1
        assert results[0].agent_id == "agent-a"
        assert results[0].decision == Decision.BLOCK

    @pytest.mark.asyncio
    async def test_list_sessions(self, sqlite_ledger: PostgresEventLedger) -> None:
        await sqlite_ledger.append(_make_event(session_id="sess-a"))
        await sqlite_ledger.append(_make_event(session_id="sess-b"))
        sessions = await sqlite_ledger.list_sessions()
        assert set(sessions) == {"sess-a", "sess-b"}

    @pytest.mark.asyncio
    async def test_list_session_summaries_attack_first_ordering(
        self, sqlite_ledger: PostgresEventLedger
    ) -> None:
        await sqlite_ledger.append(_make_event(session_id="s1", decision=Decision.ALLOW))
        await sqlite_ledger.append(_make_event(session_id="s2", decision=Decision.BLOCK))
        await sqlite_ledger.append(_make_event(session_id="s2", decision=Decision.BLOCK))
        await sqlite_ledger.append(_make_event(session_id="s2", decision=Decision.ALLOW))
        await sqlite_ledger.append(_make_event(session_id="s3", decision=Decision.BLOCK))
        await sqlite_ledger.append(_make_event(session_id="s3", decision=Decision.ALLOW))

        summaries = await sqlite_ledger.list_session_summaries()
        assert [s.session_id for s in summaries] == ["s2", "s3", "s1"]
        s2 = next(s for s in summaries if s.session_id == "s2")
        assert s2.total_events == 3
        assert s2.blocked_events == 2
        assert s2.framework == "test"

    @pytest.mark.asyncio
    async def test_list_session_summaries_framework_frozen_from_first_event(
        self, sqlite_ledger: PostgresEventLedger
    ) -> None:
        """The upsert in append() only sets `framework` on the INSERT
        branch (on_conflict_do_update's set_ clause never touches it) — a
        later event with a different framework must not change it. Mirrors
        InMemoryEventLedger's matching behavior."""
        first = _make_event(session_id="framework-drift")
        first.framework = "proxy"
        await sqlite_ledger.append(first)

        second = _make_event(session_id="framework-drift")
        second.framework = "claude-code"
        await sqlite_ledger.append(second)

        summaries = await sqlite_ledger.list_session_summaries()
        summary = next(s for s in summaries if s.session_id == "framework-drift")
        assert summary.framework == "proxy"

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
    async def test_attack_patterns_excludes_non_blocked_indicators(
        self, sqlite_ledger: PostgresEventLedger
    ) -> None:
        """attack_patterns must only reflect indicators from BLOCKed events —
        matching InMemoryEventLedger.list_agents, which filters to
        `blocked = [e for e in evts if e.decision == Decision.BLOCK]` before
        deriving patterns. An indicator the analyzer flagged on an
        ultimately-ALLOWED or REVIEW action must not leak into an agent's
        attack-pattern list."""
        await sqlite_ledger.append(_make_event(
            agent_id="agent-mixed", decision=Decision.ALLOW,
            indicators=["benign_flagged_indicator"],
        ))
        await sqlite_ledger.append(_make_event(
            agent_id="agent-mixed", decision=Decision.REVIEW,
            indicators=["review_only_indicator"],
        ))
        await sqlite_ledger.append(_make_event(
            agent_id="agent-mixed", decision=Decision.BLOCK,
            indicators=["real_attack_indicator"],
        ))
        profile = await sqlite_ledger.get_agent_profile("agent-mixed")
        assert profile is not None
        assert profile.attack_patterns == ["real_attack_indicator"]

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
