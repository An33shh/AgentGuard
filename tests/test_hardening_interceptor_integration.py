"""Integration tests: ApprovalAuthority wired into Interceptor.intercept()."""

from __future__ import annotations

import pytest

from agentguard.core.models import Decision
from agentguard.hardening.approval import ApprovalAuthority, ApprovalError
from agentguard.hardening.nonce_store import InMemoryNonceStore
from agentguard.interceptor.interceptor import Interceptor
from agentguard.ledger.event_ledger import InMemoryEventLedger
from agentguard.policy.engine import PolicyEngine
from tests.conftest import MockAnalyzer


@pytest.fixture(autouse=True)
def approval_secret(monkeypatch):
    monkeypatch.setenv("AGENTGUARD_APPROVAL_SECRET", "a" * 32)


@pytest.fixture
def hardened_interceptor(policy_engine: PolicyEngine) -> Interceptor:
    return Interceptor(
        analyzer=MockAnalyzer(),
        policy_engine=policy_engine,
        event_ledger=InMemoryEventLedger(),
        approval_authority=ApprovalAuthority(nonce_store=InMemoryNonceStore()),
    )


@pytest.fixture
def plain_interceptor(policy_engine: PolicyEngine) -> Interceptor:
    """No approval_authority configured — hardening opt-out, default behavior."""
    return Interceptor(
        analyzer=MockAnalyzer(),
        policy_engine=policy_engine,
        event_ledger=InMemoryEventLedger(),
    )


class TestApprovalIssuedOnAllow:
    @pytest.mark.asyncio
    async def test_allow_decision_gets_approval(self, hardened_interceptor: Interceptor) -> None:
        decision, event = await hardened_interceptor.intercept(
            raw_payload={"tool_name": "file.read", "parameters": {"path": "README.md"}},
            agent_goal="read the readme",
            session_id="sess-1",
        )
        assert decision == Decision.ALLOW
        assert event.approval_id != ""
        token = hardened_interceptor.get_approval_token(event.approval_id)
        assert token

    @pytest.mark.asyncio
    async def test_blocked_decision_gets_no_approval(self, hardened_interceptor: Interceptor) -> None:
        decision, event = await hardened_interceptor.intercept(
            raw_payload={"tool_name": "bash", "parameters": {"command": "rm -rf /"}},
            agent_goal="test",
            session_id="sess-2",
        )
        assert decision == Decision.BLOCK
        assert event.approval_id == ""

    @pytest.mark.asyncio
    async def test_no_hardening_configured_no_approval(self, plain_interceptor: Interceptor) -> None:
        decision, event = await plain_interceptor.intercept(
            raw_payload={"tool_name": "file.read", "parameters": {"path": "README.md"}},
            agent_goal="read the readme",
            session_id="sess-3",
        )
        assert decision == Decision.ALLOW
        assert event.approval_id == ""


class TestVerifyExecution:
    @pytest.mark.asyncio
    async def test_verify_execution_succeeds_once(self, hardened_interceptor: Interceptor) -> None:
        decision, event = await hardened_interceptor.intercept(
            raw_payload={"tool_name": "file.read", "parameters": {"path": "README.md"}},
            agent_goal="read the readme",
            session_id="sess-1",
        )
        assert decision == Decision.ALLOW
        await hardened_interceptor.verify_execution(
            approval_id=event.approval_id,
            tool_name="file.read",
            parameters={"path": "README.md"},
            session_id="sess-1",
            correlation_id=event.correlation_id,
        )

    @pytest.mark.asyncio
    async def test_verify_execution_rejects_replay(self, hardened_interceptor: Interceptor) -> None:
        _decision, event = await hardened_interceptor.intercept(
            raw_payload={"tool_name": "file.read", "parameters": {"path": "README.md"}},
            agent_goal="read the readme",
            session_id="sess-1",
        )
        await hardened_interceptor.verify_execution(
            approval_id=event.approval_id,
            tool_name="file.read",
            parameters={"path": "README.md"},
            session_id="sess-1",
            correlation_id=event.correlation_id,
        )
        with pytest.raises(ApprovalError):
            await hardened_interceptor.verify_execution(
                approval_id=event.approval_id,
                tool_name="file.read",
                parameters={"path": "README.md"},
                session_id="sess-1",
                correlation_id=event.correlation_id,
            )

    @pytest.mark.asyncio
    async def test_verify_execution_rejects_unknown_approval_id(
        self, hardened_interceptor: Interceptor
    ) -> None:
        with pytest.raises(ApprovalError, match="No pending approval"):
            await hardened_interceptor.verify_execution(
                approval_id="nonexistent",
                tool_name="file.read",
                parameters={"path": "README.md"},
                session_id="sess-1",
                correlation_id="corr-1",
            )

    @pytest.mark.asyncio
    async def test_verify_execution_rejects_param_substitution(
        self, hardened_interceptor: Interceptor
    ) -> None:
        _decision, event = await hardened_interceptor.intercept(
            raw_payload={"tool_name": "file.read", "parameters": {"path": "README.md"}},
            agent_goal="read the readme",
            session_id="sess-1",
        )
        with pytest.raises(ApprovalError, match="Action mismatch"):
            await hardened_interceptor.verify_execution(
                approval_id=event.approval_id,
                tool_name="file.read",
                parameters={"path": "/etc/shadow"},
                session_id="sess-1",
                correlation_id=event.correlation_id,
            )

    @pytest.mark.asyncio
    async def test_verify_execution_without_hardening_raises(self, plain_interceptor: Interceptor) -> None:
        with pytest.raises(ApprovalError, match="not enabled"):
            await plain_interceptor.verify_execution(
                approval_id="anything",
                tool_name="file.read",
                parameters={"path": "README.md"},
                session_id="sess-1",
                correlation_id="corr-1",
            )
