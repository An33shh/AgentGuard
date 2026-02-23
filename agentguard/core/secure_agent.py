"""High-level SecureAgent facade — wires everything from environment."""

from __future__ import annotations

import os
import uuid
import warnings
from pathlib import Path
from typing import Any

import structlog

from agentguard.analyzer.intent_analyzer import IntentAnalyzer
from agentguard.core.models import Decision, Event
from agentguard.interceptor.interceptor import Interceptor
from agentguard.ledger.event_ledger import EventLedger, InMemoryEventLedger
from agentguard.policy.engine import PolicyEngine
from agentguard.telemetry.logger import configure_logging

logger = structlog.get_logger(__name__)


class SecureAgent:
    """
    High-level facade that wires AgentGuard components together.

    Usage:
        guard = SecureAgent.from_env(goal="Summarize README.md")
        decision, event = await guard.intercept(raw_payload)

        # OpenAI Agents SDK
        hooks = guard.get_openai_hooks()
        result = await Runner.run(agent, input=msg, hooks=hooks)

        # LangGraph
        secured_graph = guard.wrap_langgraph(compiled_graph)
    """

    def __init__(
        self,
        agent_goal: str,
        interceptor: Interceptor,
        ledger: EventLedger,
        session_id: str | None = None,
        framework: str = "unknown",
    ) -> None:
        self._goal = agent_goal
        self._interceptor = interceptor
        self._ledger = ledger
        self._session_id = session_id or str(uuid.uuid4())
        self._framework = framework

    @classmethod
    def from_env(
        cls,
        goal: str,
        framework: str = "unknown",
        policy_path: str | None = None,
        session_id: str | None = None,
        ledger: EventLedger | None = None,
    ) -> "SecureAgent":
        """
        Create a SecureAgent from environment variables.

        Required env:
            ANTHROPIC_API_KEY

        Optional env:
            AGENTGUARD_POLICY_PATH  (default: policies/default.yaml)
            AGENTGUARD_LOG_LEVEL    (default: INFO)
            AGENTGUARD_ANALYZER_TIMEOUT (default: 10.0)
            AGENTGUARD_ANALYZER_MODEL (default: claude-sonnet-4-6)
        """
        log_level = os.getenv("AGENTGUARD_LOG_LEVEL", "INFO")
        configure_logging(log_level=log_level, json_logs=False)

        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            warnings.warn(
                "ANTHROPIC_API_KEY is not set. AgentGuard will fall back to medium risk "
                "(0.5) for all LLM analysis — policy rules still enforce.",
                RuntimeWarning,
                stacklevel=2,
            )

        model = os.getenv("AGENTGUARD_ANALYZER_MODEL", "claude-sonnet-4-6")
        timeout = float(os.getenv("AGENTGUARD_ANALYZER_TIMEOUT", "10.0"))

        # Resolve policy path: prefer explicit arg → env var → package default
        _default_policy = str(
            Path(__file__).parent.parent.parent / "policies" / "default.yaml"
        )
        policy_file = policy_path or os.getenv("AGENTGUARD_POLICY_PATH", _default_policy)

        analyzer = IntentAnalyzer(api_key=api_key, model=model, timeout=timeout)
        policy_engine = PolicyEngine.from_yaml(policy_file)
        event_ledger = ledger or InMemoryEventLedger()

        interceptor = Interceptor(
            analyzer=analyzer,
            policy_engine=policy_engine,
            event_ledger=event_ledger,
        )

        return cls(
            agent_goal=goal,
            interceptor=interceptor,
            ledger=event_ledger,
            session_id=session_id,
            framework=framework,
        )

    async def intercept(
        self,
        raw_payload: dict[str, Any],
        provenance: dict[str, Any] | None = None,
    ) -> tuple[Decision, Event]:
        """Intercept an action and return (decision, event)."""
        return await self._interceptor.intercept(
            raw_payload=raw_payload,
            agent_goal=self._goal,
            session_id=self._session_id,
            provenance=provenance,
            framework=self._framework,
        )

    def get_openai_hooks(self) -> Any:
        """Get OpenAI Agents SDK RunHooks implementation."""
        from agentguard.adapters.openai_adapter import AgentGuardOpenAIHooks

        return AgentGuardOpenAIHooks(
            interceptor=self._interceptor,
            agent_goal=self._goal,
            session_id=self._session_id,
        )

    def get_langgraph_adapter(self) -> Any:
        """Get LangGraph adapter for wrapping tools."""
        from agentguard.adapters.langgraph_adapter import LangGraphAdapter

        return LangGraphAdapter(
            interceptor=self._interceptor,
            agent_goal=self._goal,
            session_id=self._session_id,
        )

    def wrap_langgraph(self, compiled_graph: Any) -> Any:
        """Wrap a compiled LangGraph graph with AgentGuard middleware."""
        adapter = self.get_langgraph_adapter()
        return adapter.wrap_langgraph(compiled_graph)

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def ledger(self) -> EventLedger:
        return self._ledger
