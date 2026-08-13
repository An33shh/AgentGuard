"""Abstract base class for agent framework adapters."""

from __future__ import annotations

import abc
from typing import Any


class AgentAdapter(abc.ABC):
    """
    Abstract base class for agent framework adapters.

    Adapters bridge framework-specific hook APIs to the AgentGuard interceptor.

    Expected constructor shape for concrete adapters (not structurally
    enforced — Python ABCs don't validate `__init__` signatures the way they
    validate abstract methods, so this is documented here rather than typed):
    `__init__(self, interceptor, agent_goal: str, session_id: str,
    agent_id: str | None = None, guardrail: PromptGuardrail | None = None)`.
    `agent_id` must be threaded through to every `Interceptor.intercept()`
    call the adapter makes — omitting it forces every action through this
    adapter into the unregistered/ABAC-restricted tier regardless of what the
    calling application actually knows about its own agent's identity (see
    `OpenClawAdapter` for the reference implementation).
    """

    @abc.abstractmethod
    async def before_tool_call(
        self,
        tool_name: str,
        parameters: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> None:
        """
        Called before a tool is executed.

        Raises BlockedByAgentGuard if the action should be blocked.
        """

    @abc.abstractmethod
    def get_framework_name(self) -> str:
        """Return the framework identifier string."""
