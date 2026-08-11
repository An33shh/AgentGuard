"""Tests for HashChainedEventLedger: tamper-evident event chaining."""

from __future__ import annotations

import pytest

from agentguard.core.models import Action, Decision, Event, RiskAssessment
from agentguard.hardening.chained_ledger import (
    GENESIS_HASH,
    ChainBrokenError,
    HashChainedEventLedger,
)
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


class TestCrossTampering:
    """Tamper scenarios that touch more than one event or more than one
    session — distinct from single-field tampering already covered above."""

    @pytest.mark.asyncio
    async def test_detects_swapped_event_hashes(self, chained: HashChainedEventLedger) -> None:
        """Swapping two events' event_hash values (not modifying content)
        is a distinct attack from content tampering: the hashes themselves
        stay internally valid-looking, just attached to the wrong event."""
        e1 = _make_event()
        await chained.append(e1)
        e2 = _make_event()
        await chained.append(e2)
        e3 = _make_event()
        await chained.append(e3)

        rec1 = await chained._inner.get_event(e1.event_id)
        rec2 = await chained._inner.get_event(e2.event_id)
        rec1.event_hash, rec2.event_hash = rec2.event_hash, rec1.event_hash

        with pytest.raises(ChainBrokenError):
            await chained.verify_chain("sess-1")

    @pytest.mark.asyncio
    async def test_detects_tamper_on_non_first_event(self, chained: HashChainedEventLedger) -> None:
        """Existing coverage only tampers the first event in a chain — confirm
        detection also works when the tampered event is in the middle or at
        the end, not just conveniently the first one checked."""
        events = []
        for _ in range(5):
            e = _make_event()
            await chained.append(e)
            events.append(e)

        stored = await chained._inner.get_event(events[3].event_id)  # 4th of 5, not first
        stored.decision = Decision.BLOCK

        with pytest.raises(ChainBrokenError, match="content hash mismatch") as exc_info:
            await chained.verify_chain("sess-1")
        assert events[3].event_id in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_detects_tamper_on_last_event(self, chained: HashChainedEventLedger) -> None:
        events = []
        for _ in range(4):
            e = _make_event()
            await chained.append(e)
            events.append(e)

        stored = await chained._inner.get_event(events[-1].event_id)
        stored.decision = Decision.BLOCK

        with pytest.raises(ChainBrokenError, match="content hash mismatch"):
            await chained.verify_chain("sess-1")

    @pytest.mark.asyncio
    async def test_cross_session_splice_rejected(self, chained: HashChainedEventLedger) -> None:
        """An attacker who copies a legitimate event_hash from session A
        cannot use it to make an event in session B look chained from
        somewhere legitimate — each session's chain must start from
        GENESIS_HASH independent of what hashes exist elsewhere in storage."""
        a1 = _make_event(session_id="sess-a")
        await chained.append(a1)

        b1 = _make_event(session_id="sess-b")
        await chained.append(b1)
        stored_b1 = await chained._inner.get_event(b1.event_id)
        stored_b1.prev_event_hash = a1.event_hash  # spliced in from a foreign session

        with pytest.raises(ChainBrokenError, match="prev_hash mismatch"):
            await chained.verify_chain("sess-b")
        # Session A's own chain is untouched by the attempted splice.
        assert await chained.verify_chain("sess-a") is True

    @pytest.mark.asyncio
    async def test_detects_deleted_middle_event(self, chained: HashChainedEventLedger) -> None:
        """Deleting an event outright (not just modifying it) still breaks
        the chain: the following event's prev_event_hash no longer matches
        the (now different) preceding event actually in storage."""
        events = []
        for _ in range(4):
            e = _make_event()
            await chained.append(e)
            events.append(e)

        # InMemoryEventLedger stores events in a plain dict — delete directly.
        del chained._inner._events[events[1].event_id]
        chained._inner._sessions["sess-1"].remove(events[1].event_id)

        with pytest.raises(ChainBrokenError, match="prev_hash mismatch"):
            await chained.verify_chain("sess-1")

    @pytest.mark.asyncio
    async def test_full_forward_rewrite_is_not_detected(self, chained: HashChainedEventLedger) -> None:
        """
        Documents the mechanism's real boundary, empirically rather than
        just in prose: if an attacker tampers with event content AND
        recomputes every hash forward from that point consistently, the
        chain verifies as intact. Hash chaining alone detects inconsistent
        tampering; it does not detect a fully consistent rewrite by an
        attacker with unrestricted write access to the backing store. This
        is exactly the "no external anchor" limitation stated in the paper
        — demonstrated here, not just asserted.
        """
        from agentguard.hardening.chained_ledger import _event_content_hash

        e1 = _make_event()
        await chained.append(e1)
        e2 = _make_event()
        await chained.append(e2)

        rec1 = await chained._inner.get_event(e1.event_id)
        rec1.decision = Decision.BLOCK  # tamper
        rec1.event_hash = _event_content_hash(rec1, rec1.prev_event_hash)  # attacker recomputes forward

        rec2 = await chained._inner.get_event(e2.event_id)
        rec2.prev_event_hash = rec1.event_hash  # ...and relinks the next event to match
        rec2.event_hash = _event_content_hash(rec2, rec2.prev_event_hash)

        # No exception: a fully consistent forward rewrite is not detectable
        # by hash chaining alone. This is the documented, expected boundary.
        assert await chained.verify_chain("sess-1") is True


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
