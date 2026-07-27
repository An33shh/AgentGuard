"""GuardrailLedger — event storage for PromptGuardrail.

Separate from EventLedger (incompatible schemas).
InMemoryGuardrailLedger is the default Phase 1 implementation.
"""

from __future__ import annotations

import abc
import asyncio

from agentguard.guardrail.models import GuardrailEvent, GuardrailVerdict


class GuardrailLedger(abc.ABC):
    @abc.abstractmethod
    async def append_guardrail_event(self, event: GuardrailEvent) -> None: ...

    @abc.abstractmethod
    async def list_guardrail_events(
        self,
        session_id: str | None = None,
        verdict: GuardrailVerdict | None = None,
        limit: int = 100,
    ) -> list[GuardrailEvent]: ...


class InMemoryGuardrailLedger(GuardrailLedger):
    """Thread-safe in-memory ledger. Mirrors InMemoryEventLedger pattern."""

    def __init__(self) -> None:
        self._events: list[GuardrailEvent] = []
        self._lock = asyncio.Lock()

    async def append_guardrail_event(self, event: GuardrailEvent) -> None:
        async with self._lock:
            self._events.append(event)

    async def list_guardrail_events(
        self,
        session_id: str | None = None,
        verdict: GuardrailVerdict | None = None,
        limit: int = 100,
    ) -> list[GuardrailEvent]:
        async with self._lock:
            events = list(self._events)

        if session_id is not None:
            events = [e for e in events if e.session_id == session_id]
        if verdict is not None:
            events = [e for e in events if e.result.verdict == verdict]

        return events[-limit:]
