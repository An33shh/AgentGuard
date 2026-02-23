"""LangGraph adapter using wrap_tool middleware."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

import structlog

from agentguard.adapters.base import AgentAdapter
from agentguard.core.exceptions import BlockedByAgentGuard
from agentguard.core.models import Decision

if TYPE_CHECKING:
    from agentguard.interceptor.interceptor import Interceptor

logger = structlog.get_logger(__name__)

_BLOCKED_CONTENT = "[BLOCKED BY AGENTGUARD] This action was blocked by the security policy."


class LangGraphAdapter(AgentAdapter):
    """
    LangGraph adapter that wraps tool calls via middleware.

    Two integration patterns:

    1. **Wrap individual tools** (recommended, guaranteed coverage):
       Use ``wrap_tool()`` on each tool before building the graph, then
       pass the wrapped tools to ``ToolNode``.

    2. **Wrap a compiled graph** (best-effort, version-dependent):
       Use ``wrap_langgraph()`` which tries to patch all ``ToolNode``
       instances it finds inside the compiled graph.  If LangGraph's
       internal structure changes this may silently degrade to a warning.
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

    async def before_tool_call(
        self,
        tool_name: str,
        parameters: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> None:
        raw_payload = {
            "tool_name": tool_name,
            "parameters": parameters,
        }
        decision, event = await self._interceptor.intercept(
            raw_payload=raw_payload,
            agent_goal=self._agent_goal,
            session_id=self._session_id,
            provenance={"framework": "langgraph"},
            framework="langgraph",
        )
        if decision == Decision.BLOCK:
            raise BlockedByAgentGuard(event)

    def get_framework_name(self) -> str:
        return "langgraph"

    def wrap_tool(self, tool_fn: Callable, tool_name: str | None = None) -> Callable:
        """
        Wrap a single LangGraph tool function with AgentGuard interception.

        Returns a blocked ToolMessage instead of raising, so the graph
        continues running and the agent can handle the refusal gracefully.
        """
        name = tool_name or getattr(tool_fn, "name", getattr(tool_fn, "__name__", "unknown"))
        adapter = self

        async def guarded_tool(*args: Any, **kwargs: Any) -> Any:
            parameters = kwargs if kwargs else (args[0] if args and isinstance(args[0], dict) else {})
            try:
                await adapter.before_tool_call(name, parameters)
                return await tool_fn(*args, **kwargs)
            except BlockedByAgentGuard as exc:
                logger.warning(
                    "langgraph_tool_blocked",
                    tool=name,
                    risk_score=exc.event.assessment.risk_score,
                    reason=exc.event.assessment.reason,
                )
                try:
                    from langchain_core.messages import ToolMessage
                    return ToolMessage(
                        content=_BLOCKED_CONTENT,
                        tool_call_id=str(exc.event.event_id),
                        name=name,
                    )
                except ImportError:
                    return _BLOCKED_CONTENT

        guarded_tool.__name__ = f"guarded_{name}"
        # Preserve any attributes the original tool had (name, description, etc.)
        if hasattr(tool_fn, "name"):
            guarded_tool.name = tool_fn.name  # type: ignore[attr-defined]
        if hasattr(tool_fn, "description"):
            guarded_tool.description = tool_fn.description  # type: ignore[attr-defined]
        return guarded_tool

    def wrap_langgraph(self, compiled_graph: Any) -> Any:
        """
        Wrap a compiled LangGraph graph with AgentGuard tool interception.

        Finds all ``ToolNode`` instances in the graph's node list and wraps
        their tools in-place using ``wrap_tool()``.  This works for standard
        LangGraph graphs built with ``StateGraph`` + ``ToolNode``.

        For guaranteed coverage (e.g. custom nodes, future LangGraph versions),
        prefer wrapping tools individually via ``wrap_tool()`` before passing
        them to ``ToolNode``.
        """
        patched = 0

        # LangGraph compiled graphs expose their nodes via .nodes (dict-like)
        # Each value is typically a RunnableLambda; the underlying callable
        # is a ToolNode if it has a `tools_by_name` attribute.
        try:
            nodes = getattr(compiled_graph, "nodes", None) or {}
            for node_name, node_callable in nodes.items():
                # Walk one level of wrapping (RunnableLambda stores .func)
                candidate = getattr(node_callable, "func", node_callable)
                tools_by_name: dict[str, Any] | None = getattr(candidate, "tools_by_name", None)
                if tools_by_name is None:
                    # Some versions nest another level deep
                    candidate = getattr(candidate, "bound", candidate)
                    tools_by_name = getattr(candidate, "tools_by_name", None)

                if tools_by_name is not None:
                    for tname in list(tools_by_name.keys()):
                        original = tools_by_name[tname]
                        tools_by_name[tname] = self.wrap_tool(original, tname)
                        patched += 1
                    logger.info(
                        "langgraph_node_patched",
                        node=node_name,
                        tools_wrapped=patched,
                    )
        except Exception as exc:
            logger.warning(
                "langgraph_wrap_error",
                error=str(exc),
                hint="Use wrap_tool() on individual tools for guaranteed coverage.",
            )

        if patched == 0:
            logger.warning(
                "langgraph_no_tool_nodes_found",
                hint=(
                    "No ToolNode tools were found in the compiled graph. "
                    "Wrap individual tools with wrap_tool() before building the graph."
                ),
            )

        compiled_graph._agentguard = self
        return compiled_graph
