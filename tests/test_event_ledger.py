"""Tests for the InMemory event ledger."""

from __future__ import annotations

import pytest

from agentguard.core.models import Action, ActionType, Decision, Event, RiskAssessment
from agentguard.ledger.event_ledger import InMemoryEventLedger


def make_event(
    session_id: str = "test-session",
    tool_name: str = "file.read",
    decision: Decision = Decision.ALLOW,
    risk_score: float = 0.1,
    agent_id: str = "",
    reason: str = "test",
) -> Event:
    return Event(
        session_id=session_id,
        agent_id=agent_id,
        agent_goal="Test goal",
        action=Action(
            tool_name=tool_name,
            type=ActionType.FILE_READ,
            parameters={"path": "test.md"},
        ),
        assessment=RiskAssessment(
            risk_score=risk_score,
            reason=reason,
            indicators=[],
            analyzer_model="mock",
        ),
        decision=decision,
    )


class TestInMemoryEventLedger:
    @pytest.mark.asyncio
    async def test_append_and_get(self) -> None:
        ledger = InMemoryEventLedger()
        event = make_event()
        await ledger.append(event)

        retrieved = await ledger.get_event(event.event_id)
        assert retrieved is not None
        assert retrieved.event_id == event.event_id

    @pytest.mark.asyncio
    async def test_list_events_no_filter(self) -> None:
        ledger = InMemoryEventLedger()
        for i in range(5):
            await ledger.append(make_event(session_id=f"session-{i}"))

        events = await ledger.list_events()
        assert len(events) == 5

    @pytest.mark.asyncio
    async def test_list_events_filter_by_session(self) -> None:
        ledger = InMemoryEventLedger()
        await ledger.append(make_event(session_id="session-a"))
        await ledger.append(make_event(session_id="session-a"))
        await ledger.append(make_event(session_id="session-b"))

        events = await ledger.list_events(session_id="session-a")
        assert len(events) == 2

    @pytest.mark.asyncio
    async def test_list_events_filter_by_decision(self) -> None:
        ledger = InMemoryEventLedger()
        await ledger.append(make_event(decision=Decision.ALLOW))
        await ledger.append(make_event(decision=Decision.BLOCK))
        await ledger.append(make_event(decision=Decision.BLOCK))

        blocked = await ledger.list_events(decision=Decision.BLOCK)
        assert len(blocked) == 2

    @pytest.mark.asyncio
    async def test_list_events_filter_by_risk(self) -> None:
        ledger = InMemoryEventLedger()
        await ledger.append(make_event(risk_score=0.1))
        await ledger.append(make_event(risk_score=0.5))
        await ledger.append(make_event(risk_score=0.9))

        high_risk = await ledger.list_events(min_risk=0.6)
        assert len(high_risk) == 1
        assert high_risk[0].assessment.risk_score == 0.9

    @pytest.mark.asyncio
    async def test_list_events_filter_by_agent_id(self) -> None:
        ledger = InMemoryEventLedger()
        await ledger.append(make_event(agent_id="agent-a"))
        await ledger.append(make_event(agent_id="agent-a"))
        await ledger.append(make_event(agent_id="agent-b"))

        events = await ledger.list_events(agent_id="agent-a")
        assert len(events) == 2
        assert all(e.agent_id == "agent-a" for e in events)

    @pytest.mark.asyncio
    async def test_search_events_fulltext_composes_with_filters(self) -> None:
        ledger = InMemoryEventLedger()
        await ledger.append(make_event(reason="suspicious exfil attempt", decision=Decision.BLOCK, agent_id="agent-a"))
        await ledger.append(make_event(reason="suspicious exfil attempt", decision=Decision.ALLOW, agent_id="agent-a"))
        await ledger.append(make_event(reason="suspicious exfil attempt", decision=Decision.BLOCK, agent_id="agent-b"))
        await ledger.append(make_event(reason="unrelated benign action", decision=Decision.BLOCK, agent_id="agent-a"))

        results = await ledger.search_events_fulltext("exfil", decision=Decision.BLOCK, agent_id="agent-a")
        assert len(results) == 1
        assert results[0].agent_id == "agent-a"
        assert results[0].decision == Decision.BLOCK

    @pytest.mark.asyncio
    async def test_get_timeline_ordered(self) -> None:
        ledger = InMemoryEventLedger()
        for _ in range(3):
            await ledger.append(make_event(session_id="ordered-session"))

        timeline = await ledger.get_timeline("ordered-session")
        assert len(timeline) == 3
        # Events should be chronologically ordered
        timestamps = [e.timestamp for e in timeline]
        assert timestamps == sorted(timestamps)

    @pytest.mark.asyncio
    async def test_list_sessions(self) -> None:
        ledger = InMemoryEventLedger()
        await ledger.append(make_event(session_id="s1"))
        await ledger.append(make_event(session_id="s2"))
        await ledger.append(make_event(session_id="s1"))

        sessions = await ledger.list_sessions()
        assert set(sessions) == {"s1", "s2"}

    @pytest.mark.asyncio
    async def test_list_session_summaries_attack_first_ordering(self) -> None:
        ledger = InMemoryEventLedger()
        # s1: 1 event, 0 blocked. s2: 3 events, 2 blocked. s3: 2 events, 1 blocked.
        await ledger.append(make_event(session_id="s1", decision=Decision.ALLOW))
        await ledger.append(make_event(session_id="s2", decision=Decision.BLOCK))
        await ledger.append(make_event(session_id="s2", decision=Decision.BLOCK))
        await ledger.append(make_event(session_id="s2", decision=Decision.ALLOW))
        await ledger.append(make_event(session_id="s3", decision=Decision.BLOCK))
        await ledger.append(make_event(session_id="s3", decision=Decision.ALLOW))

        summaries = await ledger.list_session_summaries()
        assert [s.session_id for s in summaries] == ["s2", "s3", "s1"]

        s2 = next(s for s in summaries if s.session_id == "s2")
        assert s2.total_events == 3
        assert s2.blocked_events == 2
        assert s2.agent_goal == "Test goal"
        assert s2.framework  # non-empty, from the Event default

    @pytest.mark.asyncio
    async def test_list_session_summaries_framework_is_first_event_not_latest(self) -> None:
        """PostgresEventLedger's upsert only sets `framework` on the INSERT
        branch (frozen from whichever event first created the SessionRecord
        row) — InMemory must agree, not report the latest event's
        framework, or the two implementations diverge on this field."""
        ledger = InMemoryEventLedger()

        def event(framework: str) -> Event:
            e = make_event(session_id="framework-drift")
            e.framework = framework
            return e

        await ledger.append(event("proxy"))
        await ledger.append(event("claude-code"))

        summaries = await ledger.list_session_summaries()
        summary = next(s for s in summaries if s.session_id == "framework-drift")
        assert summary.framework == "proxy"

    @pytest.mark.asyncio
    async def test_timeline_summary(self) -> None:
        ledger = InMemoryEventLedger()
        await ledger.append(make_event(session_id="summary-test", decision=Decision.BLOCK, risk_score=0.9))
        await ledger.append(make_event(session_id="summary-test", decision=Decision.ALLOW, risk_score=0.1))
        await ledger.append(make_event(session_id="summary-test", decision=Decision.REVIEW, risk_score=0.6))

        summary = await ledger.get_timeline_summary("summary-test")
        assert summary is not None
        assert summary.total_events == 3
        assert summary.blocked_events == 1
        assert summary.allowed_events == 1
        assert summary.reviewed_events == 1
        assert summary.max_risk_score == 0.9

    @pytest.mark.asyncio
    async def test_get_event_not_found(self) -> None:
        ledger = InMemoryEventLedger()
        result = await ledger.get_event("nonexistent-id")
        assert result is None

    @pytest.mark.asyncio
    async def test_pagination(self) -> None:
        ledger = InMemoryEventLedger()
        for i in range(10):
            await ledger.append(make_event())

        page1 = await ledger.list_events(limit=5, offset=0)
        page2 = await ledger.list_events(limit=5, offset=5)
        assert len(page1) == 5
        assert len(page2) == 5
        # No overlap
        ids1 = {e.event_id for e in page1}
        ids2 = {e.event_id for e in page2}
        assert not ids1.intersection(ids2)
