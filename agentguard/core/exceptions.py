"""AgentGuard custom exceptions."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentguard.core.models import Event


class AgentGuardError(Exception):
    """Base exception for AgentGuard."""


class BlockedByAgentGuard(AgentGuardError):
    """Raised when an agent action is blocked by AgentGuard policy."""

    def __init__(self, event: "Event") -> None:
        self.event = event
        super().__init__(
            f"Action '{event.action.tool_name}' blocked. "
            f"Risk score: {event.assessment.risk_score:.2f}. "
            f"Reason: {event.assessment.reason}"
        )


class PolicyViolationError(AgentGuardError):
    """Raised when a deterministic policy rule is violated."""


class AnalyzerError(AgentGuardError):
    """Raised when the intent analyzer fails."""


class LedgerError(AgentGuardError):
    """Raised when the event ledger encounters an error."""


class ConfigurationError(AgentGuardError):
    """Raised when AgentGuard is misconfigured."""
