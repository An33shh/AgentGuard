"""Tests for ApprovalAuthority: per-action signed approval binding + nonce replay rejection."""

from __future__ import annotations

import asyncio

import pytest

from agentguard.hardening.approval import ApprovalAuthority, ApprovalError
from agentguard.hardening.models import compute_action_hash
from agentguard.hardening.nonce_store import InMemoryNonceStore, NonceReplayError


@pytest.fixture(autouse=True)
def approval_secret(monkeypatch):
    monkeypatch.setenv("AGENTGUARD_APPROVAL_SECRET", "a" * 32)


@pytest.fixture
def authority() -> ApprovalAuthority:
    return ApprovalAuthority(nonce_store=InMemoryNonceStore())


class TestComputeActionHash:
    def test_deterministic(self) -> None:
        h1 = compute_action_hash("file.read", {"path": "README.md"})
        h2 = compute_action_hash("file.read", {"path": "README.md"})
        assert h1 == h2

    def test_key_order_independent(self) -> None:
        h1 = compute_action_hash("http.get", {"url": "x", "method": "GET"})
        h2 = compute_action_hash("http.get", {"method": "GET", "url": "x"})
        assert h1 == h2

    def test_different_params_different_hash(self) -> None:
        h1 = compute_action_hash("bash", {"command": "ls"})
        h2 = compute_action_hash("bash", {"command": "rm -rf /"})
        assert h1 != h2


class TestIssueAndVerify:
    @pytest.mark.asyncio
    async def test_happy_path(self, authority: ApprovalAuthority) -> None:
        approval = authority.issue(
            tool_name="file.read",
            parameters={"path": "README.md"},
            session_id="sess-1",
            correlation_id="corr-1",
        )
        await authority.verify_and_consume(
            token=approval.token,
            tool_name="file.read",
            parameters={"path": "README.md"},
            session_id="sess-1",
            correlation_id="corr-1",
        )

    @pytest.mark.asyncio
    async def test_expired_approval_rejected(self, authority: ApprovalAuthority) -> None:
        approval = authority.issue(
            tool_name="file.read",
            parameters={"path": "README.md"},
            session_id="sess-1",
            correlation_id="corr-1",
            ttl_seconds=1,
        )
        await asyncio.sleep(1.5)
        with pytest.raises(ApprovalError, match="expired"):
            await authority.verify_and_consume(
                token=approval.token,
                tool_name="file.read",
                parameters={"path": "README.md"},
                session_id="sess-1",
                correlation_id="corr-1",
            )

    @pytest.mark.asyncio
    async def test_action_substitution_rejected(self, authority: ApprovalAuthority) -> None:
        """Approval issued for one action must not verify a different one."""
        approval = authority.issue(
            tool_name="file.read",
            parameters={"path": "README.md"},
            session_id="sess-1",
            correlation_id="corr-1",
        )
        with pytest.raises(ApprovalError, match="Action mismatch"):
            await authority.verify_and_consume(
                token=approval.token,
                tool_name="bash",
                parameters={"command": "rm -rf /"},
                session_id="sess-1",
                correlation_id="corr-1",
            )

    @pytest.mark.asyncio
    async def test_param_substitution_rejected(self, authority: ApprovalAuthority) -> None:
        approval = authority.issue(
            tool_name="file.write",
            parameters={"path": "notes.txt", "content": "hello"},
            session_id="sess-1",
            correlation_id="corr-1",
        )
        with pytest.raises(ApprovalError, match="Action mismatch"):
            await authority.verify_and_consume(
                token=approval.token,
                tool_name="file.write",
                parameters={"path": "notes.txt", "content": "malicious payload"},
                session_id="sess-1",
                correlation_id="corr-1",
            )

    @pytest.mark.asyncio
    async def test_session_mismatch_rejected(self, authority: ApprovalAuthority) -> None:
        approval = authority.issue(
            tool_name="file.read",
            parameters={"path": "README.md"},
            session_id="sess-1",
            correlation_id="corr-1",
        )
        with pytest.raises(ApprovalError, match="Approval session mismatch"):
            await authority.verify_and_consume(
                token=approval.token,
                tool_name="file.read",
                parameters={"path": "README.md"},
                session_id="sess-DIFFERENT",
                correlation_id="corr-1",
            )

    @pytest.mark.asyncio
    async def test_correlation_mismatch_rejected(self, authority: ApprovalAuthority) -> None:
        approval = authority.issue(
            tool_name="file.read",
            parameters={"path": "README.md"},
            session_id="sess-1",
            correlation_id="corr-1",
        )
        with pytest.raises(ApprovalError, match="Approval correlation mismatch"):
            await authority.verify_and_consume(
                token=approval.token,
                tool_name="file.read",
                parameters={"path": "README.md"},
                session_id="sess-1",
                correlation_id="corr-DIFFERENT",
            )

    @pytest.mark.asyncio
    async def test_replay_rejected(self, authority: ApprovalAuthority) -> None:
        """The same approval token cannot be verified/consumed twice."""
        approval = authority.issue(
            tool_name="file.read",
            parameters={"path": "README.md"},
            session_id="sess-1",
            correlation_id="corr-1",
        )
        await authority.verify_and_consume(
            token=approval.token,
            tool_name="file.read",
            parameters={"path": "README.md"},
            session_id="sess-1",
            correlation_id="corr-1",
        )
        with pytest.raises(ApprovalError, match="Replay detected"):
            await authority.verify_and_consume(
                token=approval.token,
                tool_name="file.read",
                parameters={"path": "README.md"},
                session_id="sess-1",
                correlation_id="corr-1",
            )

    @pytest.mark.asyncio
    async def test_garbage_token_rejected(self, authority: ApprovalAuthority) -> None:
        with pytest.raises(ApprovalError, match="Invalid approval token"):
            await authority.verify_and_consume(
                token="not-a-real-jwt",
                tool_name="file.read",
                parameters={"path": "README.md"},
                session_id="sess-1",
                correlation_id="corr-1",
            )

    @pytest.mark.asyncio
    async def test_wrong_signing_key_rejected(self, authority: ApprovalAuthority, monkeypatch) -> None:
        approval = authority.issue(
            tool_name="file.read",
            parameters={"path": "README.md"},
            session_id="sess-1",
            correlation_id="corr-1",
        )
        monkeypatch.setenv("AGENTGUARD_APPROVAL_SECRET", "b" * 32)
        with pytest.raises(ApprovalError, match="Invalid approval token"):
            await authority.verify_and_consume(
                token=approval.token,
                tool_name="file.read",
                parameters={"path": "README.md"},
                session_id="sess-1",
                correlation_id="corr-1",
            )


class TestNonceStore:
    @pytest.mark.asyncio
    async def test_consume_twice_raises(self) -> None:
        from datetime import datetime, timedelta, timezone

        store = InMemoryNonceStore()
        expires = datetime.now(timezone.utc) + timedelta(seconds=30)
        await store.consume("nonce-1", expires)
        with pytest.raises(NonceReplayError):
            await store.consume("nonce-1", expires)

    @pytest.mark.asyncio
    async def test_different_nonces_independent(self) -> None:
        from datetime import datetime, timedelta, timezone

        store = InMemoryNonceStore()
        expires = datetime.now(timezone.utc) + timedelta(seconds=30)
        await store.consume("nonce-1", expires)
        await store.consume("nonce-2", expires)  # should not raise

    @pytest.mark.asyncio
    async def test_concurrent_consume_exactly_one_wins(self) -> None:
        """
        Security-critical: N coroutines racing to consume the same nonce
        simultaneously must not let more than one succeed. The asyncio.Lock
        in InMemoryNonceStore must actually serialize consume(), not just
        appear to (a bug here would silently defeat replay protection under
        concurrent load, the exact scenario a real deployment hits).
        """
        import asyncio
        from datetime import datetime, timedelta, timezone

        store = InMemoryNonceStore()
        expires = datetime.now(timezone.utc) + timedelta(seconds=30)

        results = await asyncio.gather(
            *[store.consume("shared-nonce", expires) for _ in range(20)],
            return_exceptions=True,
        )
        successes = [r for r in results if r is None]
        replays = [r for r in results if isinstance(r, NonceReplayError)]
        assert len(successes) == 1
        assert len(replays) == 19
