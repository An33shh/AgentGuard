"""Tests for OpenAI and LangGraph adapters."""

from __future__ import annotations

import pytest

from agentguard.adapters.openai_adapter import AgentGuardOpenAIHooks
from agentguard.adapters.langgraph_adapter import LangGraphAdapter
from agentguard.core.exceptions import BlockedByAgentGuard
from agentguard.core.models import Decision
from agentguard.interceptor.interceptor import Interceptor
from agentguard.ledger.event_ledger import InMemoryEventLedger
from agentguard.policy.engine import PolicyEngine
from agentguard.policy.schema import PolicyConfig
from tests.conftest import MockAnalyzer


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def secure_interceptor() -> Interceptor:
    analyzer = MockAnalyzer()
    policy = PolicyEngine(config=PolicyConfig(
        name="adapter-test",
        risk_threshold=0.75,
        deny_tools=["bash"],
        deny_path_patterns=["~/.ssh/**", "~/.aws/credentials"],
        deny_domains=["*.ngrok.io"],
    ))
    ledger = InMemoryEventLedger()
    return Interceptor(analyzer=analyzer, policy_engine=policy, event_ledger=ledger)


# ---------------------------------------------------------------------------
# Minimal stub objects for simulating the OpenAI Agents SDK call signature
# ---------------------------------------------------------------------------

class _MockTool:
    """Minimal stand-in for an OpenAI Agents SDK Tool object."""
    def __init__(self, name: str, input: dict | None = None) -> None:
        self.name = name
        self.input = input or {}


class _MockContext:
    """Minimal stand-in for a RunContextWrapper."""
    def __init__(self, tool_input: dict | None = None) -> None:
        self.tool_input = tool_input or {}


class _MockAgent:
    """Minimal stand-in for an Agent object."""
    def __str__(self) -> str:
        return "MockAgent"


# ---------------------------------------------------------------------------
# AgentGuardOpenAIHooks tests
# ---------------------------------------------------------------------------

class TestOpenAIHooks:
    @pytest.mark.asyncio
    async def test_allows_safe_tool(self, secure_interceptor: Interceptor) -> None:
        hooks = AgentGuardOpenAIHooks(
            interceptor=secure_interceptor,
            agent_goal="Read README.md",
            session_id="openai-test",
        )
        tool = _MockTool("file.read", {"path": "README.md"})
        ctx = _MockContext({"path": "README.md"})
        # Should not raise
        await hooks.on_tool_start(ctx, _MockAgent(), tool)

    @pytest.mark.asyncio
    async def test_blocks_denied_tool(self, secure_interceptor: Interceptor) -> None:
        hooks = AgentGuardOpenAIHooks(
            interceptor=secure_interceptor,
            agent_goal="Run commands",
            session_id="openai-test-block",
        )
        tool = _MockTool("bash", {"command": "ls"})
        ctx = _MockContext({"command": "ls"})
        with pytest.raises(BlockedByAgentGuard) as exc_info:
            await hooks.on_tool_start(ctx, _MockAgent(), tool)
        assert exc_info.value.event.decision == Decision.BLOCK

    @pytest.mark.asyncio
    async def test_blocks_credential_path(self, secure_interceptor: Interceptor) -> None:
        hooks = AgentGuardOpenAIHooks(
            interceptor=secure_interceptor,
            agent_goal="Setup env",
            session_id="openai-test-cred",
        )
        tool = _MockTool("file.read", {"path": "~/.aws/credentials"})
        ctx = _MockContext({"path": "~/.aws/credentials"})
        with pytest.raises(BlockedByAgentGuard):
            await hooks.on_tool_start(ctx, _MockAgent(), tool)

    @pytest.mark.asyncio
    async def test_no_op_on_tool_end(self, secure_interceptor: Interceptor) -> None:
        hooks = AgentGuardOpenAIHooks(
            interceptor=secure_interceptor,
            agent_goal="test",
            session_id="test",
        )
        # on_tool_end should never raise
        await hooks.on_tool_end(None, None, None, "result")


# ---------------------------------------------------------------------------
# LangGraphAdapter tests
# ---------------------------------------------------------------------------

class TestLangGraphAdapter:
    @pytest.mark.asyncio
    async def test_allows_safe_tool(self, secure_interceptor: Interceptor) -> None:
        adapter = LangGraphAdapter(
            interceptor=secure_interceptor,
            agent_goal="Read README.md",
            session_id="langgraph-test",
        )
        await adapter.before_tool_call("file.read", {"path": "README.md"})

    @pytest.mark.asyncio
    async def test_blocks_ngrok_domain(self, secure_interceptor: Interceptor) -> None:
        adapter = LangGraphAdapter(
            interceptor=secure_interceptor,
            agent_goal="Summarize README",
            session_id="langgraph-test",
        )
        with pytest.raises(BlockedByAgentGuard):
            await adapter.before_tool_call(
                "http.request",
                {"url": "https://abc.ngrok.io/exfil"},
            )

    def test_get_framework_name(self, secure_interceptor: Interceptor) -> None:
        adapter = LangGraphAdapter(
            interceptor=secure_interceptor,
            agent_goal="test",
            session_id="test",
        )
        assert adapter.get_framework_name() == "langgraph"

    @pytest.mark.asyncio
    async def test_wrap_tool_safe_passes_through(self, secure_interceptor: Interceptor) -> None:
        adapter = LangGraphAdapter(
            interceptor=secure_interceptor,
            agent_goal="Read docs",
            session_id="langgraph-passthrough",
        )
        call_count = 0

        async def counting_tool(**kwargs: object) -> str:
            nonlocal call_count
            call_count += 1
            return "result"

        wrapped = adapter.wrap_tool(counting_tool, "safe_tool")
        await wrapped(query="test")
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_wrap_tool_blocked_returns_message(self, secure_interceptor: Interceptor) -> None:
        adapter = LangGraphAdapter(
            interceptor=secure_interceptor,
            agent_goal="test",
            session_id="langgraph-wrap-test",
        )

        async def fake_bash(**kwargs: object) -> str:
            return "output"

        wrapped = adapter.wrap_tool(fake_bash, "bash")
        # bash is in deny_tools — should return blocked message instead of raising
        result = await wrapped(command="rm -rf /")
        assert "BLOCKED" in str(result).upper()
