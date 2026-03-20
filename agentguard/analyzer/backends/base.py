"""Abstract base class for AgentGuard analyzer backends."""

from __future__ import annotations

from abc import ABC, abstractmethod

from agentguard.core.models import Action, RiskAssessment


class AnalyzerBackend(ABC):
    """
    Protocol every LLM provider backend must implement.

    A backend takes a normalized Action + context and returns a RiskAssessment.
    All structured output handling, retries, and API specifics live here.
    """

    @abstractmethod
    async def assess(
        self,
        action: Action,
        agent_goal: str,
        session_context: list[dict] | None = None,
    ) -> RiskAssessment:
        """
        Analyze an agent action and return a risk assessment.

        Args:
            action: The normalized action to analyze.
            agent_goal: The agent's stated objective.
            session_context: Recent prior actions in this session (for multi-step detection).

        Returns:
            RiskAssessment with risk_score 0.0–1.0, reason, and indicators.
        """
        ...

    @property
    @abstractmethod
    def provider(self) -> str:
        """Human-readable provider name (e.g. 'anthropic', 'openai', 'ollama')."""
        ...

    @property
    @abstractmethod
    def model(self) -> str:
        """Model identifier used for analysis."""
        ...
