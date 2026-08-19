"""Tests for the action interceptor pipeline."""

from __future__ import annotations

import pytest

from agentguard.core.models import ActionType, Decision
from agentguard.interceptor.interceptor import ActionNormalizer, Interceptor
from agentguard.ledger.event_ledger import InMemoryEventLedger
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
        decision, _event = await interceptor.intercept(
            raw_payload={"tool_name": "file.read", "parameters": {"path": "~/.ssh/id_rsa"}},
            agent_goal="Set up dev environment",
            session_id="test-session",
        )
        assert decision == Decision.BLOCK

    @pytest.mark.asyncio
    async def test_block_ngrok_domain(self, interceptor: Interceptor) -> None:
        decision, _event = await interceptor.intercept(
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
        import asyncio
        await interceptor.intercept(
            raw_payload={"tool_name": "file.read", "parameters": {"path": "README.md"}},
            agent_goal="Summarize",
            session_id="ledger-test",
        )
        await asyncio.sleep(0)  # yield so fire-and-forget ledger task completes
        events = await event_ledger.list_events(session_id="ledger-test")
        assert len(events) == 1

    @pytest.mark.asyncio
    async def test_high_risk_score_blocks(self, interceptor: Interceptor) -> None:
        """Mock analyzer returns 0.92 for ngrok URLs — above threshold."""
        decision, _event = await interceptor.intercept(
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
        decision, _event = await interceptor.intercept(
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

        # Regression: get_session_stats used to only check max_blocked, so a
        # session locked out via max_actions (this one — max_blocked=100,
        # never reached) incorrectly reported locked_out=False.
        stats = await inter.get_session_stats(session)
        assert stats["locked_out"] is True
        assert stats["locked_out_reason"] == "max_actions"

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

        # get_session_stats reflects the lockout...
        stats = await inter.get_session_stats(session)
        assert stats["blocked"] >= 2
        assert stats["locked_out"] is True
        assert stats["locked_out_reason"] == "max_blocked"

        # ...and reset_session actually lifts it, without needing a restart.
        reset = await inter.reset_session(session)
        assert reset is True
        assert (await inter.get_session_stats(session))["locked_out"] is False

        d, _ = await inter.intercept(
            raw_payload={"tool_name": "file.read", "parameters": {"path": "README.md"}},
            agent_goal="Task",
            session_id=session,
        )
        assert d == Decision.ALLOW

    @pytest.mark.asyncio
    async def test_reset_session_returns_false_for_unknown_session(
        self, interceptor: Interceptor
    ) -> None:
        assert await interceptor.reset_session("never-seen-session") is False

    @pytest.mark.asyncio
    async def test_get_session_stats_defaults_for_unknown_session(
        self, interceptor: Interceptor
    ) -> None:
        stats = await interceptor.get_session_stats("never-seen-session")
        assert stats["actions"] == 0
        assert stats["blocked"] == 0
        assert stats["locked_out"] is False

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


class TestShellCommandPolicyEndToEnd:
    """The deny_tools -> content-aware Bash blocking redesign, full pipeline.

    Uses a custom Interceptor (deny_tools=[] so only shell_command_policy is
    in play) rather than the shared `interceptor` fixture, which still
    deny_tools-bans bash by name for its own, unrelated tests.
    """

    def _config(self, **overrides):
        from agentguard.policy.schema import PolicyConfig
        return PolicyConfig(name="shell-e2e-test", deny_tools=[], **overrides)

    def _interceptor(self, analyzer, **policy_overrides) -> Interceptor:
        engine = PolicyEngine(config=self._config(**policy_overrides))
        return Interceptor(analyzer=analyzer, policy_engine=engine, event_ledger=InMemoryEventLedger())

    @pytest.mark.asyncio
    async def test_destructive_command_blocks_without_calling_analyzer(self) -> None:
        from unittest.mock import AsyncMock

        spy_analyzer = AsyncMock()
        inter = self._interceptor(spy_analyzer)
        decision, event = await inter.intercept(
            raw_payload={"tool_name": "bash", "parameters": {"command": "rm -rf /"}},
            agent_goal="Clean up temp files",
            session_id="shell-e2e-1",
        )
        assert decision == Decision.BLOCK
        assert event.policy_violation is not None
        assert event.policy_violation.rule_name == "shell_command_policy"
        spy_analyzer.analyze.assert_not_called()

    @pytest.mark.asyncio
    async def test_block_score_flows_into_synthesized_risk_score(self) -> None:
        """Code-review finding: shell_command_policy.block_score was defined
        as an operator-facing knob but never actually read anywhere —
        silently a no-op. Mirrors LocalClassifier.INJECTION_SCORE's role: the
        risk_score attached to the fast-path RiskAssessment when this rule
        fires, not a confidence filter on which patterns block."""
        from unittest.mock import AsyncMock

        from agentguard.policy.schema import ShellCommandPolicy

        spy_analyzer = AsyncMock()
        inter = self._interceptor(spy_analyzer, shell_command_policy=ShellCommandPolicy(block_score=0.42))
        _decision, event = await inter.intercept(
            raw_payload={"tool_name": "bash", "parameters": {"command": "rm -rf /"}},
            agent_goal="Clean up temp files",
            session_id="shell-e2e-block-score",
        )
        assert event.assessment.risk_score == 0.42

    @pytest.mark.asyncio
    async def test_benign_command_reaches_analyzer_and_is_allowed(self, mock_analyzer) -> None:
        """Not auto-passed — it genuinely goes through LLM-style risk scoring
        against the agent's stated goal, same as any other tool call."""
        inter = self._interceptor(mock_analyzer)
        decision, event = await inter.intercept(
            raw_payload={"tool_name": "bash", "parameters": {"command": "ls -la"}},
            agent_goal="List files in the current directory",
            session_id="shell-e2e-2",
        )
        assert decision == Decision.ALLOW
        assert event.assessment.analyzer_model == "mock"  # proves the mock analyzer was actually consulted

    @pytest.mark.asyncio
    async def test_obfuscated_destructive_command_caught_by_llm_layer(self, mock_analyzer) -> None:
        """The deterministic regex layer can't decode base64 and doesn't
        block this — proves that gap doesn't translate into an actual
        security regression, since the LLM layer (mocked here) still can."""
        mock_analyzer.set_score("base64", 0.95)
        inter = self._interceptor(mock_analyzer)
        decision, event = await inter.intercept(
            raw_payload={
                "tool_name": "bash",
                "parameters": {"command": 'bash -c "$(echo cm0gLXJmIC8= | base64 -d)"'},
            },
            agent_goal="Clean up temp files",
            session_id="shell-e2e-3",
        )
        assert decision == Decision.BLOCK
        assert event.policy_violation is not None
        assert event.policy_violation.rule_name == "risk_threshold"  # LLM-scored block, not the deterministic rule

    @pytest.mark.asyncio
    async def test_shell_command_fail_closed_path_now_reachable(self) -> None:
        """Regression guard for a previously-dead code path: SHELL_COMMAND
        fails closed on analyzer error (risk_score=1.0, now true for every
        action type — see IntentAnalyzer._fallback_assessment), but was
        unreachable while deny_tools blanket-blocked bash before ever
        calling the analyzer. A benign command now genuinely reaches it,
        so a real analyzer failure must fail closed here too."""
        from unittest.mock import AsyncMock, patch

        from agentguard.analyzer.backends.anthropic_backend import AnthropicBackend
        from agentguard.analyzer.intent_analyzer import IntentAnalyzer

        real_analyzer = IntentAnalyzer(backend=AnthropicBackend(api_key="fake-key"))
        inter = self._interceptor(real_analyzer)

        with patch.object(real_analyzer._backend._client.messages, "create", new_callable=AsyncMock) as mock_create:
            mock_create.side_effect = Exception("simulated upstream failure")
            decision, event = await inter.intercept(
                raw_payload={"tool_name": "bash", "parameters": {"command": "ls -la"}},
                agent_goal="List files",
                session_id="shell-e2e-4",
            )

        assert decision == Decision.BLOCK
        assert event.assessment.risk_score == 1.0
        assert event.assessment.analyzer_model == "fallback"
