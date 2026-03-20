"""High-level SecureAgent facade — wires everything from environment."""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Any

import structlog

from agentguard.analyzer.intent_analyzer import IntentAnalyzer
from agentguard.analyzer.backends import create_backend
from agentguard.core.models import Decision, Event
from agentguard.interceptor.interceptor import Interceptor
from agentguard.ledger.db import PostgresEventLedger
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
        agent_id: str | None = None,
        session_id: str | None = None,
        framework: str = "unknown",
    ) -> None:
        self._goal = agent_goal
        self._agent_id = agent_id  # explicit identity; None → auto-derived per intercept call
        self._interceptor = interceptor
        self._ledger = ledger
        self._session_id = session_id or str(uuid.uuid4())
        self._framework = framework

    @classmethod
    def from_env(
        cls,
        goal: str,
        framework: str = "unknown",
        agent_id: str | None = None,
        policy_path: str | None = None,
        session_id: str | None = None,
        ledger: EventLedger | None = None,
        analyzer_provider: str | None = None,
        analyzer_model: str | None = None,
        analyzer_api_key: str | None = None,
        analyzer_base_url: str | None = None,
    ) -> "SecureAgent":
        """
        Create a SecureAgent from environment variables.

        LLM provider is selected via AGENTGUARD_ANALYZER env var (or analyzer_provider arg):
            "anthropic"  — Claude (default if ANTHROPIC_API_KEY is set)
            "openai"     — OpenAI GPT models
            "ollama"     — Local models via Ollama (no API key needed)
            "lm_studio"  — Local models via LM Studio (no API key needed)
            "groq"       — Groq Cloud
            "together"   — Together AI

        Key env vars:
            AGENTGUARD_ANALYZER      — provider name (auto-detected if not set)
            AGENTGUARD_MODEL         — model name (provider default if not set)
            AGENTGUARD_BASE_URL      — base URL for OpenAI-compatible providers
            ANTHROPIC_API_KEY        — Anthropic API key
            OPENAI_API_KEY           — OpenAI API key
            GROQ_API_KEY             — Groq API key
            TOGETHER_API_KEY         — Together AI API key
            AGENTGUARD_POLICY_PATH   — policy file path (default: policies/default.yaml)
        """
        log_level = os.getenv("AGENTGUARD_LOG_LEVEL", "INFO")
        configure_logging(log_level=log_level, json_logs=False)

        # Resolve policy path: prefer explicit arg → env var → package default
        _default_policy = str(
            Path(__file__).parent.parent.parent / "policies" / "default.yaml"
        )
        policy_file = policy_path or os.getenv("AGENTGUARD_POLICY_PATH", _default_policy)

        backend = create_backend(
            provider=analyzer_provider,
            model=analyzer_model,
            api_key=analyzer_api_key,
            base_url=analyzer_base_url,
        )
        hedge_after = float(os.getenv("AGENTGUARD_HEDGE_AFTER", "3.0"))
        analyzer = IntentAnalyzer(backend=backend, hedge_after=hedge_after)
        policy_engine = PolicyEngine.from_yaml(policy_file)
        if ledger is not None:
            event_ledger = ledger
        elif os.getenv("DATABASE_URL"):
            event_ledger = PostgresEventLedger(os.getenv("DATABASE_URL"))
        else:
            event_ledger = InMemoryEventLedger()

        interceptor = Interceptor(
            analyzer=analyzer,
            policy_engine=policy_engine,
            event_ledger=event_ledger,
        )

        return cls(
            agent_goal=goal,
            interceptor=interceptor,
            ledger=event_ledger,
            agent_id=agent_id,
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
            agent_id=self._agent_id,
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

    def get_openclaw_adapter(self) -> Any:
        """Get OpenClaw adapter for WebSocket gateway integration."""
        from agentguard.adapters.openclaw import OpenClawAdapter

        return OpenClawAdapter(
            interceptor=self._interceptor,
            agent_goal=self._goal,
            session_id=self._session_id,
            agent_id=self._agent_id,
        )

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def ledger(self) -> EventLedger:
        return self._ledger
