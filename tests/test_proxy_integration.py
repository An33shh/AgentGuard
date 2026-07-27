"""Integration tests for the LLM API Proxy FastAPI app."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from agentguard.proxy.app import create_proxy_app


@pytest.fixture
def proxy_app():
    """Create a fresh proxy app instance for testing."""
    # Clear lru_cache singletons so each test gets a clean state
    from agentguard.proxy import dependencies
    dependencies.get_proxy_config.cache_clear()
    dependencies.get_proxy_guardrail.cache_clear()
    dependencies.get_proxy_interceptor.cache_clear()
    dependencies.get_http_client.cache_clear()
    return create_proxy_app()


@pytest.fixture
async def proxy_client(proxy_app):
    async with AsyncClient(
        transport=ASGITransport(app=proxy_app),
        base_url="http://test",
    ) as client:
        yield client


class TestProxyHealth:
    @pytest.mark.asyncio
    async def test_health_endpoint(self, proxy_client: AsyncClient) -> None:
        response = await proxy_client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    @pytest.mark.asyncio
    async def test_root_endpoint(self, proxy_client: AsyncClient) -> None:
        response = await proxy_client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "/v1/chat/completions" in data["endpoints"]
        assert "/v1/messages" in data["endpoints"]


class TestProxyRequestContext:
    @pytest.mark.asyncio
    async def test_custom_headers_extracted(self, proxy_app) -> None:
        """Test that X-AgentGuard-* headers are parsed correctly."""
        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.dependencies import extract_request_context

        class MockRequest:
            headers = {
                "X-AgentGuard-Goal": "Read files",
                "X-AgentGuard-Session": "sess-123",
                "X-AgentGuard-AgentId": "agent-456",
            }

        config = ProxyConfig()
        ctx = extract_request_context(MockRequest(), config)
        assert ctx.agent_goal == "Read files"
        assert ctx.session_id == "sess-123"
        assert ctx.agent_id == "agent-456"

    @pytest.mark.asyncio
    async def test_auth_header_fallback(self, proxy_app) -> None:
        """Test session_id derived from auth header hash when no custom header."""
        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.dependencies import extract_request_context

        class MockRequest:
            headers = {"Authorization": "Bearer sk-test-key-12345"}

        config = ProxyConfig()
        ctx1 = extract_request_context(MockRequest(), config)
        ctx2 = extract_request_context(MockRequest(), config)
        # Same key → same session_id (deterministic hash)
        assert ctx1.session_id == ctx2.session_id
        assert ctx1.session_id.startswith("proxy-")

    @pytest.mark.asyncio
    async def test_missing_headers_gets_defaults(self, proxy_app) -> None:
        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.dependencies import extract_request_context

        class MockRequest:
            headers: dict = {}

        config = ProxyConfig()
        ctx = extract_request_context(MockRequest(), config)
        assert ctx.agent_goal  # has a default
        assert ctx.session_id   # auto-generated


class TestProxyMiddleware:
    @pytest.mark.asyncio
    async def test_request_id_header_added(self, proxy_client: AsyncClient) -> None:
        response = await proxy_client.get("/health")
        assert "x-request-id" in response.headers

    @pytest.mark.asyncio
    async def test_provided_request_id_echoed(self, proxy_client: AsyncClient) -> None:
        response = await proxy_client.get(
            "/health",
            headers={"X-Request-ID": "my-test-id"},
        )
        assert response.headers["x-request-id"] == "my-test-id"
