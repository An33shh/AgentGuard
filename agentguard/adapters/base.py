"""Abstract base class for agent framework adapters."""

from __future__ import annotations

import abc
from typing import Any


class AgentAdapter(abc.ABC):
    """
    Abstract base class for agent framework adapters.

    Adapters bridge framework-specific hook APIs to the AgentGuard interceptor.
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
