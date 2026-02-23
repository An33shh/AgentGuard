"""Tests for the FastAPI endpoints."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport

from agentguard.core.models import Action, ActionType, Decision, Event, RiskAssessment
from agentguard.ledger.event_ledger import InMemoryEventLedger
from agentguard.policy.engine import PolicyEngine
from agentguard.policy.schema import PolicyConfig
from api.dependencies import get_ledger, get_policy_engine
from api.main import create_app


def make_test_event(session_id: str = "test-session", decision: Decision = Decision.ALLOW) -> Event:
    return Event(
        session_id=session_id,
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
