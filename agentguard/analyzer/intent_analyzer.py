"""Intent analyzer using Claude claude-sonnet-4-6 with forced tool_use."""

from __future__ import annotations

import time
from typing import Any

import structlog

from agentguard.core.models import Action, RiskAssessment
from agentguard.analyzer.prompts import ASSESS_RISK_TOOL, SYSTEM_PROMPT, build_user_prompt

logger = structlog.get_logger(__name__)

_FALLBACK_ASSESSMENT = RiskAssessment(
    risk_score=0.5,
    reason="analyzer_unavailable — defaulting to medium risk",
    indicators=["analyzer_error"],
    is_goal_aligned=False,
    analyzer_model="fallback",
)


class IntentAnalyzer:
    """
    Analyzes agent actions for risk using Claude claude-sonnet-4-6.

    Uses forced tool_use (structured JSON) — not text parsing — for
    machine-parseable, injection-resistant output.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-sonnet-4-6",
        timeout: float = 10.0,
        max_tokens: int = 1024,
    ) -> None:
        import anthropic

        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._model = model
        self._timeout = timeout
        self._max_tokens = max_tokens

    async def analyze(self, action: Action, agent_goal: str) -> RiskAssessment:
        """Analyze an action and return a RiskAssessment."""
        t_start = time.monotonic()
        log = logger.bind(tool=action.tool_name, action_type=action.type.value)

        try:
            response = await self._client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                system=SYSTEM_PROMPT,
                tools=[ASSESS_RISK_TOOL],
                tool_choice={"type": "tool", "name": "assess_risk"},
                messages=[
                    {"role": "user", "content": build_user_prompt(action, agent_goal)}
                ],
            )

            # Extract tool use result
            tool_result = self._extract_tool_result(response)
            if tool_result is None:
                log.warning("analyzer_no_tool_result")
                return _FALLBACK_ASSESSMENT

            latency_ms = (time.monotonic() - t_start) * 1000
            assessment = RiskAssessment(
                risk_score=tool_result["risk_score"],
                reason=tool_result["reason"],
                indicators=tool_result.get("indicators", []),
                is_goal_aligned=tool_result.get("is_goal_aligned", True),
                analyzer_model=self._model,
                latency_ms=latency_ms,
            )
            log.info(
                "analysis_complete",
                risk_score=assessment.risk_score,
                risk_level=assessment.risk_level,
                latency_ms=f"{latency_ms:.0f}ms",
            )
            return assessment

        except Exception as exc:
            latency_ms = (time.monotonic() - t_start) * 1000
            log.error("analyzer_error", error=str(exc), latency_ms=f"{latency_ms:.0f}ms")
            return RiskAssessment(
                risk_score=0.5,
                reason=f"analyzer_unavailable: {type(exc).__name__}",
                indicators=["analyzer_error"],
                is_goal_aligned=False,
                analyzer_model="fallback",
                latency_ms=latency_ms,
            )

    def _extract_tool_result(self, response: Any) -> dict | None:
        """Extract the tool use input from Claude's response."""
        for block in response.content:
            if block.type == "tool_use" and block.name == "assess_risk":
                return block.input
        return None
