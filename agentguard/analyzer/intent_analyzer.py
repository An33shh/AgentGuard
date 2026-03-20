"""Intent analyzer — provider-agnostic orchestrator with local pre-screen and request hedging."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import structlog

from agentguard.core.models import Action, ActionType, RiskAssessment
from agentguard.analyzer.backends.base import AnalyzerBackend
from agentguard.analyzer.local_classifier import LocalClassifier

logger = structlog.get_logger(__name__)

# Action types that must BLOCK on analyzer failure (fail-closed)
_FAIL_CLOSED_TYPES: frozenset[ActionType] = frozenset({
    ActionType.CREDENTIAL_ACCESS,
    ActionType.SHELL_COMMAND,
    ActionType.MEMORY_WRITE,
})


def _fallback_assessment(action: Action, reason: str, latency_ms: float) -> RiskAssessment:
    """Fail-closed: sensitive action types default to BLOCK on any error."""
    score = 1.0 if action.type in _FAIL_CLOSED_TYPES else 0.5
    return RiskAssessment(
        risk_score=score,
        reason=reason,
        indicators=["analyzer_error"],
        is_goal_aligned=False,
        analyzer_model="fallback",
        latency_ms=latency_ms,
    )


class IntentAnalyzer:
    """
    Provider-agnostic intent analyzer.

    Pipeline:
      1. LocalClassifier  — zero-latency pattern match (catches obvious prompt injection)
      2. Backend.assess() — LLM risk scoring via whichever provider is configured
      3. Request hedging  — parallel call fires after hedge_after seconds if first is slow
      4. Fail-closed      — sensitive action types default to BLOCK on any error

    Supports any backend implementing AnalyzerBackend:
      AnthropicBackend, OpenAICompatBackend (OpenAI, Ollama, Groq, LM Studio, etc.)
    """

    def __init__(
        self,
        backend: AnalyzerBackend,
        hedge_after: float = 3.0,
    ) -> None:
        self._backend = backend
        self._hedge_after = hedge_after
        self._local = LocalClassifier()

    @property
    def provider(self) -> str:
        return self._backend.provider

    @property
    def model(self) -> str:
        return self._backend.model

    async def analyze(
        self,
        action: Action,
        agent_goal: str,
        session_context: list[dict] | None = None,
    ) -> RiskAssessment:
        """Analyze an action and return a RiskAssessment."""
        t_start = time.monotonic()
        log = logger.bind(
            tool=action.tool_name,
            action_type=action.type.value,
            provider=self._backend.provider,
            model=self._backend.model,
        )

        # 1. Local classifier — zero-latency pre-screen
        local_result = self._local.classify(action)
        if local_result is not None:
            log.info(
                "local_classifier_hit",
                risk_score=local_result.risk_score,
                indicators=local_result.indicators,
            )
            return local_result

        # 2. LLM analysis with request hedging
        try:
            assessment = await self._hedged_analyze(action, agent_goal, session_context, log)
            latency_ms = (time.monotonic() - t_start) * 1000
            assessment.latency_ms = latency_ms
            log.info(
                "analysis_complete",
                risk_score=assessment.risk_score,
                risk_level=assessment.risk_level,
                latency_ms=f"{latency_ms:.0f}ms",
            )
            return assessment

        except asyncio.CancelledError:
            # CancelledError is BaseException in Python 3.8+ — explicit catch required.
            # Treat cancellation as an analyzer failure and apply fail-closed defaults.
            latency_ms = (time.monotonic() - t_start) * 1000
            log.error("analyzer_cancelled", latency_ms=f"{latency_ms:.0f}ms")
            return _fallback_assessment(action, "analyzer_cancelled", latency_ms)

        except Exception as exc:
            latency_ms = (time.monotonic() - t_start) * 1000
            log.error("analyzer_error", error=str(exc), latency_ms=f"{latency_ms:.0f}ms")
            return _fallback_assessment(
                action,
                f"analyzer_unavailable: {type(exc).__name__}",
                latency_ms,
            )

    async def _hedged_analyze(
        self,
        action: Action,
        agent_goal: str,
        session_context: list[dict] | None,
        log: Any,
    ) -> RiskAssessment:
        """
        Request hedging: fire first call immediately.
        If it takes longer than hedge_after seconds, fire a second parallel call.
        Whichever completes first wins; the other is cancelled.
        """
        task1 = asyncio.create_task(
            self._backend.assess(action, agent_goal, session_context)
        )
        try:
            return await asyncio.wait_for(asyncio.shield(task1), timeout=self._hedge_after)
        except asyncio.TimeoutError:
            log.info("hedge_triggered", hedge_after=self._hedge_after)
            task2 = asyncio.create_task(
                self._backend.assess(action, agent_goal, session_context)
            )
            done, pending = await asyncio.wait({task1, task2}, return_when=asyncio.FIRST_COMPLETED)
            for p in pending:
                p.cancel()
                try:
                    await p
                except BaseException as p_exc:
                    if not isinstance(p_exc, asyncio.CancelledError):
                        log.debug("hedge_pending_task_error", error_type=type(p_exc).__name__)
            # Prefer a successful result when both tasks finish simultaneously.
            winner = None
            for task in done:
                if not task.exception():
                    winner = task
                    break
            if winner is None:
                # All completed tasks raised — re-raise the first exception.
                winner = next(iter(done))
                raise winner.exception()  # type: ignore[misc]
            return winner.result()
