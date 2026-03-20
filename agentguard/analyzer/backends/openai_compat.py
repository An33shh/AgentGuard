"""OpenAI-compatible backend — works with OpenAI, Ollama, LM Studio, Groq, Together AI, and any provider with an OpenAI-compatible API."""

from __future__ import annotations

import json

from agentguard.core.models import Action, RiskAssessment
from agentguard.analyzer.backends.base import AnalyzerBackend
from agentguard.analyzer.prompts import SYSTEM_PROMPT, build_user_prompt

# OpenAI function-calling schema (converted from Anthropic input_schema format)
_TOOL = {
    "type": "function",
    "function": {
        "name": "assess_risk",
        "description": "Submit a structured risk assessment for the intercepted agent action.",
        "parameters": {
            "type": "object",
            "properties": {
                "risk_score": {
                    "type": "number",
                    "description": "Risk score from 0.0 (safe) to 1.0 (certain attack).",
                    "minimum": 0.0,
                    "maximum": 1.0,
                },
                "reason": {
                    "type": "string",
                    "description": "Concise explanation (1-2 sentences) of the risk score.",
                },
                "indicators": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Specific threat indicators observed.",
                },
                "is_goal_aligned": {
                    "type": "boolean",
                    "description": "True if the action is aligned with the agent's stated goal.",
                },
            },
            "required": ["risk_score", "reason", "indicators", "is_goal_aligned"],
        },
    },
}


class OpenAICompatBackend(AnalyzerBackend):
    """
    OpenAI-compatible backend supporting any provider with an OpenAI-style API.

    Works out of the box with:
      - OpenAI          (api_key=OPENAI_API_KEY)
      - Ollama          (base_url="http://localhost:11434/v1", api_key="ollama")
      - LM Studio       (base_url="http://localhost:1234/v1", api_key="lm-studio")
      - Groq            (base_url="https://api.groq.com/openai/v1", api_key=GROQ_API_KEY)
      - Together AI     (base_url="https://api.together.xyz/v1", api_key=TOGETHER_API_KEY)
      - Any other OpenAI-compatible endpoint

    Note: the model must support function/tool calling for structured output.
    Ollama models with tool support: llama3.1, llama3.2, mistral-nemo, qwen2.5.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gpt-4o",
        base_url: str | None = None,
        provider_name: str = "openai",
    ) -> None:
        from openai import AsyncOpenAI

        self._client = AsyncOpenAI(
            api_key=api_key or "local",
            base_url=base_url,
        )
        self._model = model
        self._provider_name = provider_name

    @property
    def provider(self) -> str:
        return self._provider_name

    @property
    def model(self) -> str:
        return self._model

    async def assess(
        self,
        action: Action,
        agent_goal: str,
        session_context: list[dict] | None = None,
    ) -> RiskAssessment:
        response = await self._client.chat.completions.create(
            model=self._model,
            tools=[_TOOL],
            tool_choice={"type": "function", "function": {"name": "assess_risk"}},
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_prompt(action, agent_goal, session_context)},
            ],
        )

        message = response.choices[0].message
        if message.tool_calls:
            for tc in message.tool_calls:
                if tc.function.name == "assess_risk":
                    result = json.loads(tc.function.arguments)
                    return RiskAssessment(
                        risk_score=result["risk_score"],
                        reason=result["reason"],
                        indicators=result.get("indicators", []),
                        is_goal_aligned=result.get("is_goal_aligned", True),
                        analyzer_model=f"{self._provider_name}/{self._model}",
                    )

        raise ValueError(f"{self._provider_name} response contained no assess_risk tool call")
