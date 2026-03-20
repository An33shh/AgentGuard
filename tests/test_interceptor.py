"""Tests for the action interceptor pipeline."""

from __future__ import annotations

import pytest

from agentguard.core.models import ActionType, Decision
from agentguard.interceptor.interceptor import ActionNormalizer, Interceptor
from agentguard.policy.engine import PolicyEngine
from agentguard.policy.schema import SessionLimits


class TestActionNormalizer:
    def test_from_dict_basic(self) -> None:
        payload = {"tool_name": "file.read", "parameters": {"path": "README.md"}}
        action = ActionNormalizer.from_dict(payload)
        assert action.tool_name == "file.read"
        assert action.parameters == {"path": "README.md"}

    def test_from_dict_infers_file_read(self) -> None:
        payload = {"tool_name": "file.read", "parameters": {"path": "README.md"}}
        action = ActionNormalizer.from_dict(payload)
        assert action.type == ActionType.FILE_READ

    def test_from_dict_credential_path_override(self) -> None:
        payload = {"tool_name": "file.read", "parameters": {"path": "~/.ssh/id_rsa"}}
        action = ActionNormalizer.from_dict(payload)
        assert action.type == ActionType.CREDENTIAL_ACCESS

    def test_from_dict_aws_credential_override(self) -> None:
        payload = {"tool_name": "file.read", "parameters": {"path": "~/.aws/credentials"}}
        action = ActionNormalizer.from_dict(payload)
        assert action.type == ActionType.CREDENTIAL_ACCESS

    def test_from_dict_http_request(self) -> None:
        payload = {"tool_name": "http.request", "parameters": {"url": "https://example.com"}}
        action = ActionNormalizer.from_dict(payload)
        assert action.type == ActionType.HTTP_REQUEST

    def test_from_dict_memory_write(self) -> None:
        payload = {"tool_name": "memory.write", "parameters": {"key": "x", "value": "y"}}
        action = ActionNormalizer.from_dict(payload)
        assert action.type == ActionType.MEMORY_WRITE

    def test_from_openai_tool_call(self) -> None:
        import json
        tc = {
            "function": {
                "name": "file.read",
                "arguments": json.dumps({"path": "README.md"}),
            }
        }
        action = ActionNormalizer.from_openai_tool_call(tc)
        assert action.tool_name == "file.read"
        assert action.parameters == {"path": "README.md"}

    def test_from_openai_tool_call_credential(self) -> None:
        import json
        tc = {
            "function": {
                "name": "file.read",
                "arguments": json.dumps({"path": "~/.aws/credentials"}),
            }
        }
        action = ActionNormalizer.from_openai_tool_call(tc)
        assert action.type == ActionType.CREDENTIAL_ACCESS


class TestInterceptor:
    @pytest.mark.asyncio
    async def test_allow_legitimate_action(self, interceptor: Interceptor) -> None:
        decision, event = await interceptor.intercept(
            raw_payload={"tool_name": "file.read", "parameters": {"path": "README.md"}},
            agent_goal="Summarize README.md",
            session_id="test-session",
        )
        assert decision == Decision.ALLOW
        assert event.action.tool_name == "file.read"

    @pytest.mark.asyncio
    async def test_block_denied_tool(self, interceptor: Interceptor) -> None:
        decision, event = await interceptor.intercept(
            raw_payload={"tool_name": "bash", "parameters": {"command": "ls -la"}},
            agent_goal="List files",
            session_id="test-session",
        )
        assert decision == Decision.BLOCK
        assert event.policy_violation is not None
        assert event.policy_violation.rule_name == "deny_tools"

    @pytest.mark.asyncio
    async def test_block_credential_path(self, interceptor: Interceptor) -> None:
        decision, event = await interceptor.intercept(
            raw_payload={"tool_name": "file.read", "parameters": {"path": "~/.ssh/id_rsa"}},
            agent_goal="Set up dev environment",
            session_id="test-session",
        )
        assert decision == Decision.BLOCK

    @pytest.mark.asyncio
    async def test_block_ngrok_domain(self, interceptor: Interceptor) -> None:
        decision, event = await interceptor.intercept(
            raw_payload={
                "tool_name": "http.request",
                "parameters": {"url": "https://abc123.ngrok.io/exfil"},
            },
            agent_goal="Summarize README.md",
            session_id="test-session",
        )
        assert decision == Decision.BLOCK

    @pytest.mark.asyncio
    async def test_event_logged_to_ledger(self, interceptor: Interceptor, event_ledger) -> None:
        await interceptor.intercept(
            raw_payload={"tool_name": "file.read", "parameters": {"path": "README.md"}},
            agent_goal="Summarize",
            session_id="ledger-test",
        )
        events = await event_ledger.list_events(session_id="ledger-test")
        assert len(events) == 1

    @pytest.mark.asyncio
    async def test_high_risk_score_blocks(self, interceptor: Interceptor) -> None:
        """Mock analyzer returns 0.92 for ngrok URLs — above threshold."""
        decision, event = await interceptor.intercept(
            raw_payload={
                "tool_name": "http.request",
                "parameters": {"url": "https://abc123.ngrok.io/"},
            },
            agent_goal="Summarize README.md",
            session_id="risk-test",
        )
        assert decision == Decision.BLOCK

    @pytest.mark.asyncio
    async def test_review_decision_propagates(
        self, interceptor: Interceptor, mock_analyzer
    ) -> None:
        """Risk score in the review band (0.60–0.74) returns REVIEW, not ALLOW."""
        mock_analyzer.set_score("special_tool", 0.65)
        decision, event = await interceptor.intercept(
            raw_payload={"tool_name": "special_tool", "parameters": {}},
            agent_goal="Some task",
            session_id="review-test",
        )
        assert decision == Decision.REVIEW

    @pytest.mark.asyncio
    async def test_session_max_actions_enforced(
        self, policy_engine, event_ledger, mock_analyzer
    ) -> None:
        """Interceptor blocks once session reaches max_actions limit."""
        tight_engine = PolicyEngine(config=policy_engine.config.model_copy(
            update={"session_limits": SessionLimits(max_actions=3, max_blocked=100)}
        ))
        inter = Interceptor(
            analyzer=mock_analyzer,
            policy_engine=tight_engine,
            event_ledger=event_ledger,
        )
        session = "limit-test"
        payload = {"tool_name": "file.read", "parameters": {"path": "README.md"}}
        for _ in range(3):
            d, _ = await inter.intercept(raw_payload=payload, agent_goal="Task", session_id=session)
            assert d == Decision.ALLOW

        # 4th request must be blocked by session limit
        d, event = await inter.intercept(raw_payload=payload, agent_goal="Task", session_id=session)
        assert d == Decision.BLOCK
        assert event.policy_violation is not None
        assert event.policy_violation.rule_name == "session_limits"

    @pytest.mark.asyncio
    async def test_session_max_blocked_enforced(
        self, policy_engine, event_ledger, mock_analyzer
    ) -> None:
        """Interceptor blocks once session reaches max_blocked limit."""
        tight_engine = PolicyEngine(config=policy_engine.config.model_copy(
            update={"session_limits": SessionLimits(max_actions=100, max_blocked=2)}
        ))
        inter = Interceptor(
            analyzer=mock_analyzer,
            policy_engine=tight_engine,
            event_ledger=event_ledger,
        )
        session = "blocked-limit-test"
        deny_payload = {"tool_name": "bash", "parameters": {}}
        for _ in range(2):
            d, _ = await inter.intercept(raw_payload=deny_payload, agent_goal="Task", session_id=session)
            assert d == Decision.BLOCK

        # Any further action is now blocked by max_blocked session limit
        d, event = await inter.intercept(
            raw_payload={"tool_name": "file.read", "parameters": {"path": "README.md"}},
            agent_goal="Task",
            session_id=session,
        )
        assert d == Decision.BLOCK
        assert event.policy_violation.rule_name == "session_limits"

    @pytest.mark.asyncio
    async def test_pipeline_error_fails_closed(
        self, policy_engine, event_ledger
    ) -> None:
        """If the analyzer raises an unexpected exception, intercept() blocks fail-closed."""
        from unittest.mock import AsyncMock

        broken_analyzer = AsyncMock()
        broken_analyzer.analyze = AsyncMock(side_effect=RuntimeError("unexpected crash"))
        inter = Interceptor(
            analyzer=broken_analyzer,
            policy_engine=policy_engine,
            event_ledger=event_ledger,
        )
        decision, event = await inter.intercept(
            raw_payload={"tool_name": "file.read", "parameters": {"path": "README.md"}},
            agent_goal="Summarize",
            session_id="error-test",
        )
        assert decision == Decision.BLOCK
        assert "pipeline_error" in event.assessment.indicators
