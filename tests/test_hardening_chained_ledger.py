"""Tests for HashChainedEventLedger: tamper-evident event chaining."""

from __future__ import annotations

import pytest

from agentguard.core.models import Action, Decision, Event, RiskAssessment
from agentguard.hardening.chained_ledger import GENESIS_HASH, ChainBrokenError, HashChainedEventLedger
from agentguard.ledger.event_ledger import InMemoryEventLedger


def _make_event(session_id: str = "sess-1", tool_name: str = "file.read") -> Event:
    return Event(
        session_id=session_id,
        agent_id="agent-1",
        agent_goal="test goal",
        action=Action(tool_name=tool_name, parameters={"path": "README.md"}),
        assessment=RiskAssessment(risk_score=0.1, reason="test"),
        decision=Decision.ALLOW,
    )


@pytest.fixture
def chained() -> HashChainedEventLedger:
    return HashChainedEventLedger(InMemoryEventLedger())


class TestAppendChaining:
    @pytest.mark.asyncio
    async def test_first_event_chains_from_genesis(self, chained: HashChainedEventLedger) -> None:
        event = _make_event()
        await chained.append(event)
        assert event.prev_event_hash == GENESIS_HASH
        assert event.event_hash != ""

    @pytest.mark.asyncio
    async def test_second_event_chains_from_first(self, chained: HashChainedEventLedger) -> None:
        e1 = _make_event()
        await chained.append(e1)
        e2 = _make_event()
        await chained.append(e2)
        assert e2.prev_event_hash == e1.event_hash

    @pytest.mark.asyncio
    async def test_different_sessions_independent_chains(self, chained: HashChainedEventLedger) -> None:
        e1 = _make_event(session_id="sess-a")
        await chained.append(e1)
        e2 = _make_event(session_id="sess-b")
        await chained.append(e2)
        assert e2.prev_event_hash == GENESIS_HASH


class TestVerifyChain:
    @pytest.mark.asyncio
    async def test_untampered_chain_verifies(self, chained: HashChainedEventLedger) -> None:
        for _ in range(5):
            await chained.append(_make_event())
        assert await chained.verify_chain("sess-1") is True

    @pytest.mark.asyncio
    async def test_empty_session_verifies(self, chained: HashChainedEventLedger) -> None:
        assert await chained.verify_chain("no-such-session") is True

    @pytest.mark.asyncio
    async def test_detects_content_tampering(self, chained: HashChainedEventLedger) -> None:
        e1 = _make_event()
        await chained.append(e1)
        e2 = _make_event()
        await chained.append(e2)

        # Simulate an attacker modifying a stored event's decision after the
        # fact (e.g. BLOCK -> ALLOW to launder a rejected action into an
        # apparently-approved one).
        stored = await chained._inner.get_event(e1.event_id)
        stored.decision = Decision.BLOCK

        with pytest.raises(ChainBrokenError, match="content hash mismatch"):
            await chained.verify_chain("sess-1")

    @pytest.mark.asyncio
    async def test_detects_prev_hash_tampering(self, chained: HashChainedEventLedger) -> None:
        e1 = _make_event()
        await chained.append(e1)
        e2 = _make_event()
        await chained.append(e2)

        # Simulate an attacker forging prev_event_hash to point somewhere else.
        stored = await chained._inner.get_event(e2.event_id)
        stored.prev_event_hash = "f" * 64

        with pytest.raises(ChainBrokenError, match="prev_hash mismatch"):
            await chained.verify_chain("sess-1")


class TestRestartSafety:
    @pytest.mark.asyncio
    async def test_new_wrapper_continues_chain_from_storage(self) -> None:
        """A fresh HashChainedEventLedger (simulating a process restart) must
        seed its chain head from the last persisted event, not GENESIS_HASH."""
        inner = InMemoryEventLedger()
        first_wrapper = HashChainedEventLedger(inner)
        e1 = _make_event()
        await first_wrapper.append(e1)

        second_wrapper = HashChainedEventLedger(inner)
        e2 = _make_event()
        await second_wrapper.append(e2)

        assert e2.prev_event_hash == e1.event_hash
        assert await second_wrapper.verify_chain("sess-1") is True
