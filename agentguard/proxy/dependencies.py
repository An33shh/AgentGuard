"""Dependency injection for the LLM API Proxy."""

from __future__ import annotations

import hashlib
import uuid
from functools import lru_cache
from typing import Annotated, Any

import httpx
import structlog
from fastapi import Depends, Request

from agentguard.proxy.config import ProxyConfig
from agentguard.proxy.models import ProxyRequestContext

logger = structlog.get_logger(__name__)


@lru_cache(maxsize=1)
def get_proxy_config() -> ProxyConfig:
    return ProxyConfig()


@lru_cache(maxsize=1)
def get_http_client() -> httpx.AsyncClient:
    """Shared httpx client for upstream requests. Created once, reused across requests."""
    config = get_proxy_config()
    return httpx.AsyncClient(
        timeout=httpx.Timeout(
            connect=config.upstream_connect_timeout,
            read=config.upstream_read_timeout,
            write=30.0,
            pool=5.0,
        ),
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        follow_redirects=False,
    )


@lru_cache(maxsize=1)
def get_proxy_interceptor() -> Any:
    """Build and cache the AgentGuard Interceptor for proxy use."""
    from agentguard.analyzer.intent_analyzer import IntentAnalyzer
    from agentguard.analyzer.backends import create_backend
    from agentguard.interceptor.interceptor import Interceptor
    from agentguard.ledger.event_ledger import InMemoryEventLedger
    from agentguard.policy.engine import PolicyEngine
    import os
    from pathlib import Path

    config = get_proxy_config()
    _cwd_policy = Path.cwd() / "policies" / "default.yaml"
    _bundled_policy = Path(__file__).parent.parent / "core" / "policies" / "default.yaml"
    _default_policy = str(_cwd_policy if _cwd_policy.exists() else _bundled_policy)
    policy_file = config.policy_path or os.getenv("AGENTGUARD_POLICY_PATH", _default_policy)

    backend = create_backend()
    hedge_after = float(os.getenv("AGENTGUARD_HEDGE_AFTER", "1.0"))
    analyzer = IntentAnalyzer(backend=backend, hedge_after=hedge_after)
    policy_engine = PolicyEngine.from_yaml(policy_file)

    # Use PostgresEventLedger when DATABASE_URL is configured so proxy events
    # are visible in the dashboard alongside main API events.
    database_url = os.getenv("DATABASE_URL", "")
    if database_url:
        from agentguard.ledger.db import PostgresEventLedger
        ledger = PostgresEventLedger(database_url)
    else:
        ledger = InMemoryEventLedger()

    return Interceptor(analyzer=analyzer, policy_engine=policy_engine, event_ledger=ledger)


@lru_cache(maxsize=1)
def get_proxy_guardrail() -> Any | None:
    """Build and cache the PromptGuardrail for proxy use, or None if not configured."""
    config = get_proxy_config()
    if not config.guardrail_mode:
        return None
    from agentguard.guardrail.guardrail import PromptGuardrail
    return PromptGuardrail.from_env(
        mode=config.guardrail_mode,
        deep_analysis=config.guardrail_deep_analysis,
    )


def extract_request_context(request: Request, config: ProxyConfig) -> ProxyRequestContext:
    """
    Extract agent identity from the request.

    Priority:
    1. Custom X-AgentGuard-* headers (explicit, most reliable)
    2. System prompt content (best-effort fallback)
    3. Auth header hash (anonymous fallback)
    """
    # Custom headers (highest priority)
    goal = request.headers.get(config.goal_header, "").strip()
    session_id = request.headers.get(config.session_header, "").strip()
    agent_id = request.headers.get(config.agent_id_header, "").strip()

    # Fallback: derive from auth header hash so sessions are stable per API key
    if not session_id:
        auth = request.headers.get("Authorization", request.headers.get("x-api-key", ""))
        if auth:
            key_hash = hashlib.sha256(auth.encode()).hexdigest()[:16]
            session_id = f"proxy-{key_hash}"
        else:
            session_id = str(uuid.uuid4())

    if not agent_id:
        agent_id = f"proxy-agent-{session_id[:8]}"

    if not goal:
        goal = "LLM API Proxy Agent"

    return ProxyRequestContext(
        agent_goal=goal,
        session_id=session_id,
        agent_id=agent_id,
    )
