"""Tests for ABAC policy rules and dynamic session demotion."""

from __future__ import annotations

import pytest

from agentguard.core.models import Action, ActionType, Decision
from agentguard.interceptor.interceptor import Interceptor
from agentguard.ledger.event_ledger import InMemoryEventLedger
from agentguard.policy.engine import PolicyEngine
from agentguard.policy.schema import DemotionConfig, PolicyConfig


def _make_action(tool: str, path: str = "README.md") -> Action:
    return Action(
        tool_name=tool,
        type=ActionType.FILE_READ,
        parameters={"path": path},
    )


def _make_interceptor(config: PolicyConfig, default_score: float = 0.3) -> Interceptor:
    """Build an interceptor with a simple mock analyzer."""
    from tests.conftest import MockAnalyzer
    return Interceptor(
        analyzer=MockAnalyzer(default_score=default_score),
        policy_engine=PolicyEngine(config=config),
        event_ledger=InMemoryEventLedger(),
    )


# ---------------------------------------------------------------------------
# ABAC: deny_unregistered_tools
# ---------------------------------------------------------------------------

class TestABAC:
    def _config(self) -> PolicyConfig:
        return PolicyConfig(
            name="abac-test",
            risk_threshold=0.75,
            review_threshold=0.60,
            deny_unregistered_tools=["git.push", "email.send"],
        )

    @pytest.mark.asyncio
    async def test_unregistered_agent_blocked_on_sensitive_tool(self) -> None:
        interceptor = _make_interceptor(self._config())
        decision, event = await interceptor.intercept(
            raw_payload={"tool_name": "git.push", "parameters": {}},
            agent_goal="Deploy code",
            session_id="unregistered-session",
            agent_id=None,  # unregistered
        )
        assert decision == Decision.BLOCK
        assert event.policy_violation is not None
        assert event.policy_violation.rule_name == "deny_unregistered_tools"
        assert event.agent_is_registered is False

    @pytest.mark.asyncio
    async def test_registered_agent_allowed_on_sensitive_tool(self) -> None:
        interceptor = _make_interceptor(self._config())
        decision, event = await interceptor.intercept(
            raw_payload={"tool_name": "git.push", "parameters": {}},
            agent_goal="Deploy code",
            session_id="registered-session",
            agent_id="agent-prod-deployer-001",  # explicitly registered
        )
        assert decision == Decision.ALLOW
        assert event.agent_is_registered is True

    @pytest.mark.asyncio
    async def test_unregistered_agent_allowed_on_safe_tool(self) -> None:
        interceptor = _make_interceptor(self._config())
        decision, _ = await interceptor.intercept(
            raw_payload={"tool_name": "file.read", "parameters": {"path": "README.md"}},
            agent_goal="Summarize README",
            session_id="unregistered-safe",
            agent_id=None,
        )
        assert decision == Decision.ALLOW

    @pytest.mark.asyncio
    async def test_wildcard_pattern_in_deny_unregistered(self) -> None:
        config = PolicyConfig(
            name="wildcard-test",
            risk_threshold=0.75,
            review_threshold=0.60,
            deny_unregistered_tools=["git.*"],
        )
        interceptor = _make_interceptor(config)
        for tool in ["git.push", "git.commit", "git.rebase"]:
            decision, _ = await interceptor.intercept(
                raw_payload={"tool_name": tool, "parameters": {}},
                agent_goal="manage repo",
                session_id=f"unregistered-{tool}",
                agent_id=None,
            )
            assert decision == Decision.BLOCK, f"{tool} should be blocked"


# ---------------------------------------------------------------------------
# Dynamic session demotion
# ---------------------------------------------------------------------------

class TestSessionDemotion:
    def _demoting_config(self) -> PolicyConfig:
        return PolicyConfig(
            name="demotion-test",
            risk_threshold=0.75,
            review_threshold=0.60,
            demotion=DemotionConfig(
                enabled=True,
                trigger_blocked_count=2,
                demoted_risk_threshold=0.40,
                demoted_review_threshold=0.25,
            ),
        )

    def test_effective_thresholds_before_demotion(self) -> None:
        engine = PolicyEngine(config=self._demoting_config())
        risk, review = engine.effective_thresholds(session_blocked=1)
        assert risk == 0.75
        assert review == 0.60

    def test_effective_thresholds_after_demotion(self) -> None:
        engine = PolicyEngine(config=self._demoting_config())
        risk, review = engine.effective_thresholds(session_blocked=2)
        assert risk == 0.40
        assert review == 0.25

    def test_effective_thresholds_well_above_trigger(self) -> None:
        engine = PolicyEngine(config=self._demoting_config())
        risk, review = engine.effective_thresholds(session_blocked=10)
        assert risk == 0.40
        assert review == 0.25

    def test_demotion_disabled_always_uses_base_thresholds(self) -> None:
        config = PolicyConfig(
            name="no-demotion",
            risk_threshold=0.75,
            review_threshold=0.60,
        )
        engine = PolicyEngine(config=config)
        risk, review = engine.effective_thresholds(session_blocked=100)
        assert risk == 0.75
        assert review == 0.60

    @pytest.mark.asyncio
    async def test_demoted_session_blocks_medium_risk_action(self) -> None:
        """After demotion, a score of 0.45 should BLOCK (threshold dropped to 0.40)."""
        interceptor = _make_interceptor(self._demoting_config(), default_score=0.45)

        # Trigger demotion by racking up 2 blocks via deny_tools
        config_with_block = PolicyConfig(
            name="demotion-trigger",
            risk_threshold=0.75,
            review_threshold=0.60,
            deny_tools=["shell.execute"],
            demotion=DemotionConfig(
                enabled=True,
                trigger_blocked_count=2,
                demoted_risk_threshold=0.40,
                demoted_review_threshold=0.25,
            ),
        )
        interceptor2 = _make_interceptor(config_with_block, default_score=0.45)

        for i in range(2):
            await interceptor2.intercept(
                raw_payload={"tool_name": "shell.execute", "parameters": {"command": "ls"}},
                agent_goal="test",
                session_id="demote-me",
            )

        # Now a medium-risk (0.45) safe-looking action should be BLOCKED under demoted threshold
        decision, event = await interceptor2.intercept(
            raw_payload={"tool_name": "file.read", "parameters": {"path": "report.txt"}},
            agent_goal="test",
            session_id="demote-me",
        )
        assert decision == Decision.BLOCK
        assert "0.40" in event.policy_violation.detail


# ---------------------------------------------------------------------------
# evaluate_risk with threshold overrides
# ---------------------------------------------------------------------------

class TestEvaluateRiskOverrides:
    def test_custom_threshold_blocks_lower_score(self) -> None:
        engine = PolicyEngine(config=PolicyConfig(
            name="t", risk_threshold=0.75, review_threshold=0.60
        ))
        decision, violation = engine.evaluate_risk(0.55, risk_threshold=0.50)
        assert decision == Decision.BLOCK

    def test_custom_review_threshold(self) -> None:
        engine = PolicyEngine(config=PolicyConfig(
            name="t", risk_threshold=0.75, review_threshold=0.60
        ))
        decision, _ = engine.evaluate_risk(0.30, risk_threshold=0.75, review_threshold=0.25)
        assert decision == Decision.REVIEW

    def test_no_override_uses_config(self) -> None:
        engine = PolicyEngine(config=PolicyConfig(
            name="t", risk_threshold=0.75, review_threshold=0.60
        ))
        assert engine.evaluate_risk(0.50)[0] == Decision.ALLOW
        assert engine.evaluate_risk(0.65)[0] == Decision.REVIEW
        assert engine.evaluate_risk(0.80)[0] == Decision.BLOCK
