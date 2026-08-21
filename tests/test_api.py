"""Tests for the FastAPI endpoints."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from agentguard.core.models import Action, ActionType, Decision, Event, RiskAssessment
from agentguard.interceptor.interceptor import Interceptor
from agentguard.ledger.event_ledger import InMemoryEventLedger
from agentguard.policy.engine import PolicyEngine
from agentguard.policy.schema import PolicyConfig
from api.dependencies import get_interceptor, get_ledger, get_policy_engine
from api.main import create_app


def make_test_event(
    session_id: str = "test-session",
    decision: Decision = Decision.ALLOW,
    agent_id: str = "",
) -> Event:
    return Event(
        session_id=session_id,
        agent_id=agent_id,
        agent_goal="Test goal",
        action=Action(
            tool_name="file.read",
            type=ActionType.FILE_READ,
            parameters={"path": "README.md"},
        ),
        assessment=RiskAssessment(
            risk_score=0.1,
            reason="test",
            indicators=[],
            analyzer_model="mock",
        ),
        decision=decision,
    )


@pytest.fixture
def test_ledger() -> InMemoryEventLedger:
    return InMemoryEventLedger()


@pytest.fixture
def test_policy_engine() -> PolicyEngine:
    return PolicyEngine(config=PolicyConfig(
        name="test",
        risk_threshold=0.75,
        deny_tools=["bash"],
    ))


@pytest.fixture
def test_app(test_ledger: InMemoryEventLedger, test_policy_engine: PolicyEngine):
    app = create_app()
    app.dependency_overrides[get_ledger] = lambda: test_ledger
    app.dependency_overrides[get_policy_engine] = lambda: test_policy_engine
    # get_interceptor() builds its own Interceptor from the *module-level*
    # get_policy_engine()/get_ledger() calls rather than declared Depends
    # params, so overriding those two alone does not affect it — it must be
    # overridden directly, or /api/v1/intercept would construct a real
    # IntentAnalyzer backend (requiring a live API key) instead of using the
    # test fixtures.
    from unittest.mock import AsyncMock
    stub_analyzer = AsyncMock()
    stub_analyzer.analyze.return_value = RiskAssessment(
        risk_score=0.1,
        reason="stub allow",
        indicators=[],
        analyzer_model="mock",
    )
    test_interceptor = Interceptor(
        analyzer=stub_analyzer,
        policy_engine=test_policy_engine,
        event_ledger=test_ledger,
    )
    app.dependency_overrides[get_interceptor] = lambda: test_interceptor
    return app


@pytest.mark.asyncio
async def test_health_endpoint(test_app) -> None:
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
        resp = await client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_list_events_empty(test_app, test_ledger) -> None:
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
        resp = await client.get("/api/v1/events")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_list_events_with_data(test_app, test_ledger) -> None:
    event = make_test_event()
    await test_ledger.append(event)

    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
        resp = await client.get("/api/v1/events")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["event_id"] == event.event_id


@pytest.mark.asyncio
async def test_get_event_by_id(test_app, test_ledger) -> None:
    event = make_test_event()
    await test_ledger.append(event)

    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
        resp = await client.get(f"/api/v1/events/{event.event_id}")
    assert resp.status_code == 200
    assert resp.json()["event_id"] == event.event_id


@pytest.mark.asyncio
async def test_get_event_not_found(test_app) -> None:
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
        resp = await client.get("/api/v1/events/nonexistent-id")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_insight_not_found_returns_structured_error(test_app) -> None:
    """Regression: get_insight used to raise a plain HTTPException whose
    string detail got mapped to error_code=INTERNAL_ERROR by the global
    handler, misclassifying a real 404 as a server error."""
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
        resp = await client.get("/api/v1/insights/nonexistent-event-id")
    assert resp.status_code == 404
    assert resp.json()["error_code"] == "NOT_FOUND"


@pytest.mark.asyncio
async def test_list_events_filter_by_agent_id(test_app, test_ledger) -> None:
    await test_ledger.append(make_test_event(agent_id="agent-a"))
    await test_ledger.append(make_test_event(agent_id="agent-b"))

    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
        resp = await client.get("/api/v1/events", params={"agent_id": "agent-a"})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["agent_id"] == "agent-a"


@pytest.mark.asyncio
async def test_get_timeline(test_app, test_ledger) -> None:
    for _ in range(3):
        await test_ledger.append(make_test_event(session_id="timeline-session"))

    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
        resp = await client.get("/api/v1/timeline?session_id=timeline-session")
    assert resp.status_code == 200
    assert len(resp.json()) == 3


@pytest.mark.asyncio
async def test_list_sessions(test_app, test_ledger) -> None:
    await test_ledger.append(make_test_event(session_id="s1"))
    await test_ledger.append(make_test_event(session_id="s2"))

    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
        resp = await client.get("/api/v1/sessions")
    assert resp.status_code == 200
    sessions = resp.json()
    assert set(sessions) == {"s1", "s2"}


@pytest.mark.asyncio
async def test_list_session_summaries(test_app, test_ledger) -> None:
    await test_ledger.append(make_test_event(session_id="s1", decision=Decision.ALLOW))
    await test_ledger.append(make_test_event(session_id="s2", decision=Decision.BLOCK))

    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
        resp = await client.get("/api/v1/sessions/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert {s["session_id"] for s in data} == {"s1", "s2"}
    s2 = next(s for s in data if s["session_id"] == "s2")
    assert s2["blocked_events"] == 1
    assert s2["total_events"] == 1


@pytest.mark.asyncio
async def test_get_policy(test_app) -> None:
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
        resp = await client.get("/api/v1/policies")
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "test"
    assert data["risk_threshold"] == 0.75


@pytest.mark.asyncio
async def test_validate_policy_valid(test_app) -> None:
    valid_yaml = """
policy:
  name: valid-test
  risk_threshold: 0.70
  deny_tools:
    - bash
"""
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
        resp = await client.post("/api/v1/policies/validate", json={"yaml": valid_yaml})
    assert resp.status_code == 200
    assert resp.json()["valid"] is True


@pytest.mark.asyncio
async def test_stats_endpoint(test_app, test_ledger) -> None:
    await test_ledger.append(make_test_event(decision=Decision.BLOCK))
    await test_ledger.append(make_test_event(decision=Decision.ALLOW))

    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
        resp = await client.get("/api/v1/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_events"] == 2
    assert data["blocked_events"] == 1


@pytest.mark.asyncio
async def test_intercept_policy_blocked_populates_taxonomy_from_violation(test_app) -> None:
    """Regression test: RiskAssessment has no mitre_technique/owasp_category/
    policy_rule fields — the endpoint must derive them from
    event.policy_violation, not the assessment, or this 500s (it used to)."""
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/intercept",
            json={
                "tool_name": "bash",
                "parameters": {"command": "ls"},
                "goal": "List files",
                "session_id": "intercept-test-block",
            },
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "block"
    assert data["policy_rule"] is not None
    assert data["mitre_technique"] is not None
    assert data["owasp_category"] is not None


@pytest.mark.asyncio
async def test_intercept_allowed_has_no_policy_violation_taxonomy(test_app) -> None:
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/intercept",
            json={
                "tool_name": "file.read",
                "parameters": {"path": "README.md"},
                "goal": "Read the readme",
                "session_id": "intercept-test-allow",
            },
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "allow"
    assert data["policy_rule"] is None
    assert data["mitre_technique"] is None
    assert data["owasp_category"] is None


@pytest.mark.asyncio
async def test_intercept_client_claimed_agent_id_does_not_bypass_abac(test_ledger: InMemoryEventLedger) -> None:
    """Regression test: a pentest found body.agent_id (an unauthenticated
    JSON field — any caller can set it to any string) forwarded straight
    into Interceptor.intercept()'s agent_id param, which flips
    is_registered=True and skips deny_unregistered_tools entirely. Confirmed
    live: {"tool_name": "git.push", "agent_id": "literally-anything"}
    bypassed the ABAC rule completely. Same class of bug already fixed for
    the proxy's X-AgentGuard-AgentId header — this is the second instance."""
    from unittest.mock import AsyncMock

    abac_policy_engine = PolicyEngine(config=PolicyConfig(
        name="abac-test",
        risk_threshold=0.75,
        deny_unregistered_tools=["git.push"],
    ))
    stub_analyzer = AsyncMock()
    stub_analyzer.analyze.return_value = RiskAssessment(
        risk_score=0.1, reason="stub allow", indicators=[], analyzer_model="mock",
    )
    interceptor = Interceptor(analyzer=stub_analyzer, policy_engine=abac_policy_engine, event_ledger=test_ledger)

    app = create_app()
    app.dependency_overrides[get_ledger] = lambda: test_ledger
    app.dependency_overrides[get_policy_engine] = lambda: abac_policy_engine
    app.dependency_overrides[get_interceptor] = lambda: interceptor

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/intercept",
            json={
                "tool_name": "git.push",
                "parameters": {},
                "goal": "Deploy code",
                "session_id": "abac-bypass-attempt",
                "agent_id": "literally-anything-i-typed",
            },
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "block"
    assert data["policy_rule"] == "deny_unregistered_tools"
