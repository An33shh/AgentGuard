"""Anthropic Claude backend for AgentGuard intent analysis."""

from __future__ import annotations

from agentguard.core.models import Action, RiskAssessment
from agentguard.analyzer.backends.base import AnalyzerBackend
from agentguard.analyzer.prompts import ASSESS_RISK_TOOL, SYSTEM_PROMPT, build_user_prompt

# Anthropic tool schema (input_schema format)
_TOOL = ASSESS_RISK_TOOL


class AnthropicBackend(AnalyzerBackend):
    """
    Uses Anthropic Claude with forced tool_use for structured risk scoring.

    Supports all Claude models. Recommended: claude-sonnet-4-6 (best speed/accuracy balance).

    Configuration:
        ANTHROPIC_API_KEY=sk-ant-...
        AGENTGUARD_MODEL=claude-sonnet-4-6   (optional)
    """

    def __init__(self, api_key: str | None = None, model: str = "claude-sonnet-4-6") -> None:
        import anthropic

        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._model = model

    @property
    def provider(self) -> str:
        return "anthropic"

    @property
    def model(self) -> str:
        return self._model

    async def assess(
        self,
        action: Action,
        agent_goal: str,
        session_context: list[dict] | None = None,
    ) -> RiskAssessment:
        response = await self._client.messages.create(
            model=self._model,
            max_tokens=512,
            system=SYSTEM_PROMPT,
            tools=[_TOOL],
            tool_choice={"type": "tool", "name": "assess_risk"},
            messages=[
                {"role": "user", "content": build_user_prompt(action, agent_goal, session_context)}
            ],
        )

        for block in response.content:
            if block.type == "tool_use" and block.name == "assess_risk":
                result = block.input
                return RiskAssessment(
                    risk_score=result["risk_score"],
                    reason=result["reason"],
                    indicators=result.get("indicators", []),
                    is_goal_aligned=result.get("is_goal_aligned", True),
                    analyzer_model=self._model,
                )

        raise ValueError("Anthropic response contained no assess_risk tool call")
