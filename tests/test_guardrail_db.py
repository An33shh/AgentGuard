"""Integration tests for PostgresGuardrailLedger against SQLite."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from agentguard.guardrail.db import PostgresGuardrailLedger
from agentguard.guardrail.models import (
    ContextType,
    DetectionCategory,
    GuardrailDetection,
    GuardrailEvent,
    GuardrailMode,
    GuardrailResult,
    GuardrailVerdict,
)


@pytest.fixture
async def guardrail_ledger(tmp_path):
    db_path = tmp_path / "guardrail_test.db"
    ledger = PostgresGuardrailLedger(f"sqlite+aiosqlite:///{db_path}")
    await ledger.create_tables()
    yield ledger
    await ledger.close()


def _make_guardrail_event(
    session_id: str = "sess-001",
    agent_id: str = "agent-test",
    verdict: GuardrailVerdict = GuardrailVerdict.ALLOW,
    detections: list[GuardrailDetection] | None = None,
) -> GuardrailEvent:
    now = datetime.now(timezone.utc)
    result = GuardrailResult(
        scan_id=uuid.uuid4().hex,
        verdict=verdict,
        context_type=ContextType.USER_INPUT,
        mode=GuardrailMode.ENFORCE,
        detections=detections or [],
        redacted_text=None,
        analyzer_model="local_scanner",
        latency_ms=2.5,
        timestamp=now,
    )
    return GuardrailEvent(
        event_id=uuid.uuid4().hex,
        session_id=session_id,
        agent_id=agent_id,
        result=result,
        text_hash="a" * 64,
        text_length=42,
        timestamp=now,
    )


class TestPostgresGuardrailLedgerBasic:
    @pytest.mark.asyncio
    async def test_append_and_list(self, guardrail_ledger: PostgresGuardrailLedger) -> None:
        event = _make_guardrail_event()
        await guardrail_ledger.append_guardrail_event(event)
        events = await guardrail_ledger.list_guardrail_events()
        assert len(events) == 1
        assert events[0].event_id == event.event_id

    @pytest.mark.asyncio
    async def test_filter_by_session(self, guardrail_ledger: PostgresGuardrailLedger) -> None:
        await guardrail_ledger.append_guardrail_event(_make_guardrail_event(session_id="sess-a"))
        await guardrail_ledger.append_guardrail_event(_make_guardrail_event(session_id="sess-b"))
        results = await guardrail_ledger.list_guardrail_events(session_id="sess-a")
        assert len(results) == 1
        assert results[0].session_id == "sess-a"

    @pytest.mark.asyncio
    async def test_filter_by_verdict(self, guardrail_ledger: PostgresGuardrailLedger) -> None:
        await guardrail_ledger.append_guardrail_event(_make_guardrail_event(verdict=GuardrailVerdict.BLOCK))
        await guardrail_ledger.append_guardrail_event(_make_guardrail_event(verdict=GuardrailVerdict.ALLOW))
        blocked = await guardrail_ledger.list_guardrail_events(verdict=GuardrailVerdict.BLOCK)
        assert len(blocked) == 1
        assert blocked[0].result.verdict == GuardrailVerdict.BLOCK

    @pytest.mark.asyncio
    async def test_detections_roundtrip(self, guardrail_ledger: PostgresGuardrailLedger) -> None:
        detection = GuardrailDetection(
            category=DetectionCategory.PROMPT_INJECTION,
            pattern_name="ignore_instructions",
            matched_snippet="ignore previous instructions",
            start_offset=0,
            end_offset=28,
            confidence=0.95,
        )
        event = _make_guardrail_event(detections=[detection])
        await guardrail_ledger.append_guardrail_event(event)
        results = await guardrail_ledger.list_guardrail_events()
        assert len(results[0].result.detections) == 1
        d = results[0].result.detections[0]
        assert d.category == DetectionCategory.PROMPT_INJECTION
        assert d.confidence == 0.95

    @pytest.mark.asyncio
    async def test_limit_respected(self, guardrail_ledger: PostgresGuardrailLedger) -> None:
        for _ in range(5):
            await guardrail_ledger.append_guardrail_event(_make_guardrail_event())
        results = await guardrail_ledger.list_guardrail_events(limit=3)
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_get_stats(self, guardrail_ledger: PostgresGuardrailLedger) -> None:
        await guardrail_ledger.append_guardrail_event(_make_guardrail_event(verdict=GuardrailVerdict.BLOCK))
        await guardrail_ledger.append_guardrail_event(_make_guardrail_event(verdict=GuardrailVerdict.REDACT))
        await guardrail_ledger.append_guardrail_event(_make_guardrail_event(verdict=GuardrailVerdict.ALLOW))
        stats = await guardrail_ledger.get_stats()
        assert stats["total_scans"] == 3
        assert stats["blocked"] == 1
        assert stats["redacted"] == 1
        assert stats["allowed"] == 1

    @pytest.mark.asyncio
    async def test_empty_stats(self, guardrail_ledger: PostgresGuardrailLedger) -> None:
        stats = await guardrail_ledger.get_stats()
        assert stats["total_scans"] == 0

    @pytest.mark.asyncio
    async def test_raw_text_never_stored(self, guardrail_ledger: PostgresGuardrailLedger) -> None:
        """Verify only hash is stored, never raw text."""
        event = _make_guardrail_event()
        await guardrail_ledger.append_guardrail_event(event)
        results = await guardrail_ledger.list_guardrail_events()
        assert results[0].result.redacted_text is None
        assert len(results[0].text_hash) == 64  # SHA-256 hex
