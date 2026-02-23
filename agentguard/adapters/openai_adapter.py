"""OpenAI Agents SDK adapter using RunHooks."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog

from agentguard.core.exceptions import BlockedByAgentGuard
from agentguard.core.models import Decision

if TYPE_CHECKING:
    from agentguard.interceptor.interceptor import Interceptor

logger = structlog.get_logger(__name__)

# Inherit from the real RunHooks when the openai-agents package is installed;
# fall back to object so the class can be imported in environments without it.
try:
    from agents import RunHooks as _RunHooksBase
except ImportError:
    _RunHooksBase = object  # type: ignore[assignment,misc]


class AgentGuardOpenAIHooks(_RunHooksBase):  # type: ignore[misc]
    """
    OpenAI Agents SDK RunHooks implementation.

    Usage:
        hooks = guard.get_openai_hooks()
        result = await Runner.run(agent, input=msg, hooks=hooks)
    """

    def __init__(
        self,
        interceptor: "Interceptor",
        agent_goal: str,
        session_id: str,
    ) -> None:
        self._interceptor = interceptor
        self._agent_goal = agent_goal
        self._session_id = session_id

    async def on_tool_start(
        self,
        context: Any,
        agent: Any,
        tool: Any,
    ) -> None:
        """Called before a tool is executed by the OpenAI Agents SDK."""
        tool_name = getattr(tool, "name", str(tool))

        # The OpenAI Agents SDK passes tool input via context.tool_use_input
        # in newer versions, or as a keyword argument in on_function_tool_start.
        # We try several attribute locations to be forward-compatible.
        parameters: dict[str, Any] = {}
        for attr in ("tool_use_input", "tool_input", "input", "args"):
            value = getattr(context, attr, None)
            if isinstance(value, dict):
                parameters = value
                break
        if not parameters:
            # Last resort: check the tool object itself
            for attr in ("input", "args", "kwargs"):
                value = getattr(tool, attr, None)
                if isinstance(value, dict):
                    parameters = value
                    break

        raw_payload = {
            "tool_name": tool_name,
            "parameters": parameters,
        }

        decision, event = await self._interceptor.intercept(
            raw_payload=raw_payload,
            agent_goal=self._agent_goal,
            session_id=self._session_id,
            provenance={"framework": "openai", "agent": str(agent)},
            framework="openai",
        )

        if decision == Decision.BLOCK:
            logger.warning(
                "openai_tool_blocked",
                tool=tool_name,
                risk_score=event.assessment.risk_score,
                reason=event.assessment.reason,
            )
            raise BlockedByAgentGuard(event)

    async def on_tool_end(self, context: Any, agent: Any, tool: Any, result: Any) -> None:
        """Called after a tool completes (no-op for AgentGuard)."""

    async def on_agent_start(self, context: Any, agent: Any) -> None:
        """Called when an agent starts (no-op)."""

    async def on_agent_end(self, context: Any, agent: Any, output: Any) -> None:
        """Called when an agent ends (no-op)."""
