"""Tests for JWT authentication, rate limiting, and auth HTTP endpoints."""

from __future__ import annotations

import os
import time
import pytest

import jwt
from httpx import AsyncClient, ASGITransport

from agentguard.auth.jwt_utils import create_access_token, verify_token
from agentguard.auth.rate_limiter import RateLimiter, reset_rate_limiter


# ---------------------------------------------------------------------------
# JWT utils
# ---------------------------------------------------------------------------

class TestJwtUtils:
    def setup_method(self) -> None:
        os.environ["AGENTGUARD_JWT_SECRET"] = "test-secret-for-unit-tests-32bytes!!"
        os.environ["AGENTGUARD_JWT_EXPIRE_SECONDS"] = "3600"

    def teardown_method(self) -> None:
        os.environ.pop("AGENTGUARD_JWT_SECRET", None)
        os.environ.pop("AGENTGUARD_JWT_EXPIRE_SECONDS", None)

    def test_create_and_verify_round_trip(self) -> None:
        token = create_access_token({"sub": "api_client"})
        payload = verify_token(token)
        assert payload["sub"] == "api_client"

    def test_verify_rejects_tampered_token(self) -> None:
        token = create_access_token({"sub": "api_client"})
        tampered = token[:-5] + "XXXXX"
        with pytest.raises(jwt.InvalidTokenError):
            verify_token(tampered)

    def test_verify_rejects_expired_token(self) -> None:
        os.environ["AGENTGUARD_JWT_EXPIRE_SECONDS"] = "0"
        token = create_access_token({"sub": "api_client"})
        time.sleep(0.1)
        with pytest.raises(jwt.ExpiredSignatureError):
            verify_token(token)

    def test_token_contains_iat_and_exp(self) -> None:
        token = create_access_token({"sub": "api_client"})
        payload = verify_token(token)
        assert "iat" in payload
        assert "exp" in payload
        assert payload["exp"] > payload["iat"]

    def test_missing_secret_raises(self) -> None:
        os.environ.pop("AGENTGUARD_JWT_SECRET", None)
        with pytest.raises(RuntimeError, match="AGENTGUARD_JWT_SECRET"):
            create_access_token({"sub": "test"})


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_allows_requests_within_limit(self) -> None:
        limiter = RateLimiter(requests_per_window=5, window_seconds=60)
        for _ in range(5):
            assert await limiter.is_allowed("client-a") is True

    @pytest.mark.asyncio
    async def test_blocks_requests_exceeding_limit(self) -> None:
        limiter = RateLimiter(requests_per_window=3, window_seconds=60)
        for _ in range(3):
            await limiter.is_allowed("client-b")
        assert await limiter.is_allowed("client-b") is False

    @pytest.mark.asyncio
    async def test_different_clients_have_independent_buckets(self) -> None:
        limiter = RateLimiter(requests_per_window=2, window_seconds=60)
        await limiter.is_allowed("client-x")
        await limiter.is_allowed("client-x")
        assert await limiter.is_allowed("client-x") is False
        # client-y is unaffected
        assert await limiter.is_allowed("client-y") is True

    @pytest.mark.asyncio
    async def test_sliding_window_expires_old_requests(self) -> None:
        limiter = RateLimiter(requests_per_window=2, window_seconds=0.1)
        await limiter.is_allowed("client-z")
        await limiter.is_allowed("client-z")
        assert await limiter.is_allowed("client-z") is False
        time.sleep(0.15)
        # After window expires, requests should be allowed again
        assert await limiter.is_allowed("client-z") is True

    @pytest.mark.asyncio
    async def test_remaining_count_decrements(self) -> None:
        limiter = RateLimiter(requests_per_window=10, window_seconds=60)
        assert limiter.remaining("new-client") == 10
        await limiter.is_allowed("new-client")
        await limiter.is_allowed("new-client")
        assert limiter.remaining("new-client") == 8


# ---------------------------------------------------------------------------
# HTTP-level auth endpoint tests
# ---------------------------------------------------------------------------

_TEST_API_KEY = "test-api-key-do-not-use-in-prod"
_TEST_JWT_SECRET = "test-secret-for-unit-tests-32bytes!!"


@pytest.fixture(autouse=False)
def auth_env(monkeypatch):
    """Set auth env vars and reset rate limiter before/after each test."""
    monkeypatch.setenv("AGENTGUARD_API_KEY", _TEST_API_KEY)
    monkeypatch.setenv("AGENTGUARD_JWT_SECRET", _TEST_JWT_SECRET)
    monkeypatch.setenv("AGENTGUARD_JWT_EXPIRE_SECONDS", "3600")
    reset_rate_limiter()
    yield
    reset_rate_limiter()


@pytest.fixture
def auth_app(auth_env):
    """FastAPI app with auth enabled."""
    from api.dependencies import get_ledger, get_policy_engine
    from api.main import create_app
    from agentguard.ledger.event_ledger import InMemoryEventLedger
    from agentguard.policy.engine import PolicyEngine
    from agentguard.policy.schema import PolicyConfig

    app = create_app()
    app.dependency_overrides[get_ledger] = lambda: InMemoryEventLedger()
    app.dependency_overrides[get_policy_engine] = lambda: PolicyEngine(
        config=PolicyConfig(name="test", risk_threshold=0.75, review_threshold=0.60)
    )
    return app


class TestAuthEndpoint:
    @pytest.mark.asyncio
    async def test_valid_api_key_returns_token(self, auth_app) -> None:
        async with AsyncClient(transport=ASGITransport(app=auth_app), base_url="http://test") as client:
            resp = await client.post("/api/v1/auth/token", json={"api_key": _TEST_API_KEY})
        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert body["token_type"] == "bearer"
        assert body["expires_in"] == 3600

    @pytest.mark.asyncio
    async def test_invalid_api_key_returns_401(self, auth_app) -> None:
        async with AsyncClient(transport=ASGITransport(app=auth_app), base_url="http://test") as client:
            resp = await client.post("/api/v1/auth/token", json={"api_key": "wrong-key"})
        assert resp.status_code == 401
        body = resp.json()
        assert "Invalid API key" in body.get("message", body.get("detail", ""))

    @pytest.mark.asyncio
    async def test_missing_api_key_returns_401(self, auth_app) -> None:
        async with AsyncClient(transport=ASGITransport(app=auth_app), base_url="http://test") as client:
            resp = await client.post("/api/v1/auth/token", json={})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_returned_token_is_valid_jwt(self, auth_app) -> None:
        async with AsyncClient(transport=ASGITransport(app=auth_app), base_url="http://test") as client:
            resp = await client.post("/api/v1/auth/token", json={"api_key": _TEST_API_KEY})
        token = resp.json()["access_token"]
        payload = verify_token(token)
        assert payload["sub"] == "api_client"

    @pytest.mark.asyncio
    async def test_token_grants_access_to_protected_route(self, auth_app) -> None:
        async with AsyncClient(transport=ASGITransport(app=auth_app), base_url="http://test") as client:
            token_resp = await client.post("/api/v1/auth/token", json={"api_key": _TEST_API_KEY})
            token = token_resp.json()["access_token"]
            events_resp = await client.get(
                "/api/v1/events",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert events_resp.status_code == 200

    @pytest.mark.asyncio
    async def test_protected_route_rejects_missing_token(self, auth_app) -> None:
        async with AsyncClient(transport=ASGITransport(app=auth_app), base_url="http://test") as client:
            resp = await client.get("/api/v1/events")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_protected_route_rejects_tampered_token(self, auth_app) -> None:
        async with AsyncClient(transport=ASGITransport(app=auth_app), base_url="http://test") as client:
            token_resp = await client.post("/api/v1/auth/token", json={"api_key": _TEST_API_KEY})
            token = token_resp.json()["access_token"]
            tampered = token[:-5] + "XXXXX"
            resp = await client.get(
                "/api/v1/events",
                headers={"Authorization": f"Bearer {tampered}"},
            )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_auth_token_endpoint_rate_limited(self, auth_app) -> None:
        """/auth/token applies a strict per-client rate limit to prevent brute-force."""
        from api.routes.auth import _AUTH_RATE_LIMIT
        reset_rate_limiter()
        async with AsyncClient(transport=ASGITransport(app=auth_app), base_url="http://test") as client:
            # Exhaust the auth-specific rate limit
            for _ in range(_AUTH_RATE_LIMIT):
                await client.post("/api/v1/auth/token", json={"api_key": "wrong"})
            # Next request must be rate-limited
            resp = await client.post("/api/v1/auth/token", json={"api_key": "wrong"})
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers


# ---------------------------------------------------------------------------
# validate_auth_config startup validation
# ---------------------------------------------------------------------------

class TestValidateAuthConfig:
    def test_no_env_vars_passes(self, monkeypatch) -> None:
        """Auth disabled (no vars set) — no error."""
        monkeypatch.delenv("AGENTGUARD_API_KEY", raising=False)
        monkeypatch.delenv("AGENTGUARD_JWT_SECRET", raising=False)
        from agentguard.auth.jwt_utils import validate_auth_config
        validate_auth_config()  # must not raise

    def test_both_vars_set_passes(self, monkeypatch) -> None:
        monkeypatch.setenv("AGENTGUARD_API_KEY", "some-key")
        monkeypatch.setenv("AGENTGUARD_JWT_SECRET", "a-secret-that-is-at-least-32-bytes!")
        from agentguard.auth.jwt_utils import validate_auth_config
        validate_auth_config()  # must not raise

    def test_api_key_without_secret_raises(self, monkeypatch) -> None:
        monkeypatch.setenv("AGENTGUARD_API_KEY", "some-key")
        monkeypatch.delenv("AGENTGUARD_JWT_SECRET", raising=False)
        from agentguard.auth.jwt_utils import validate_auth_config
        with pytest.raises(RuntimeError, match="AGENTGUARD_JWT_SECRET"):
            validate_auth_config()

    def test_secret_without_api_key_raises(self, monkeypatch) -> None:
        monkeypatch.delenv("AGENTGUARD_API_KEY", raising=False)
        monkeypatch.setenv("AGENTGUARD_JWT_SECRET", "a-secret-that-is-at-least-32-bytes!")
        from agentguard.auth.jwt_utils import validate_auth_config
        with pytest.raises(RuntimeError):
            validate_auth_config()

    def test_short_secret_raises(self, monkeypatch) -> None:
        monkeypatch.setenv("AGENTGUARD_API_KEY", "some-key")
        monkeypatch.setenv("AGENTGUARD_JWT_SECRET", "tooshort")
        from agentguard.auth.jwt_utils import validate_auth_config
        with pytest.raises(RuntimeError, match="32"):
            validate_auth_config()
