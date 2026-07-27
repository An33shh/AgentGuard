"""OpenAI Agents SDK adapter using RunHooks."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import structlog

from agentguard.core.exceptions import AgentGuardError, BlockedByAgentGuard
from agentguard.core.models import Decision, ProvenanceSourceType, ProvenanceTag

if TYPE_CHECKING:
    from agentguard.guardrail.guardrail import PromptGuardrail
    from agentguard.interceptor.interceptor import Interceptor


def _extract_result_text(result: Any) -> str:
    """Extract text content from a tool result for guardrail scanning."""
    if isinstance(result, str):
        return result
    if hasattr(result, "content"):
        content = result.content
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            return " ".join(str(b) for b in content)
    if isinstance(result, dict):
        return json.dumps(result)
    return str(result)

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
        guardrail: "PromptGuardrail | None" = None,
    ) -> None:
        self._interceptor = interceptor
        self._agent_goal = agent_goal
        self._session_id = session_id
        self._guardrail = guardrail

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
            provenance_tags=[
                ProvenanceTag(
                    source_type=ProvenanceSourceType.SYSTEM,
                    label="openai_hooks",
                    value=str(agent)[:80],
                )
            ],
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
        """Scan tool result for injection/credential/PII before it reaches the LLM."""
        if self._guardrail is None:
            return

        from agentguard.guardrail.models import ContextType, GuardrailVerdict

        tool_name = getattr(tool, "name", str(tool))
        text = _extract_result_text(result)

        scan_result = await self._guardrail.scan(text, ContextType.TOOL_RESPONSE)

        if scan_result.verdict in (GuardrailVerdict.BLOCK, GuardrailVerdict.REDACT):
            # on_tool_end cannot replace the result — blocking is the only safe option.
            # REDACT is also blocked here: leaking PII/credentials to the LLM is worse
            # than stopping the run.
            logger.warning(
                "openai_tool_result_blocked_by_guardrail",
                tool=tool_name,
                verdict=scan_result.verdict.value,
                detections=[d.pattern_name for d in scan_result.detections],
            )
            raise AgentGuardError(
                f"Tool result from '{tool_name}' blocked by guardrail "
                f"(verdict={scan_result.verdict.value}, "
                f"detections={[d.pattern_name for d in scan_result.detections]})"
            )

    async def on_agent_start(self, context: Any, agent: Any) -> None:
        """Called when an agent starts (no-op)."""

    async def on_agent_end(self, context: Any, agent: Any, output: Any) -> None:
        """Called when an agent ends (no-op)."""
