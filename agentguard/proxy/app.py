"""
LLM API Proxy — FastAPI application factory.

Runs as a standalone service on port 8748 (separate from the main API on 8747).
Acts as a transparent proxy in front of OpenAI and Anthropic APIs.

Usage:
    uvicorn agentguard.proxy.app:app --port 8748 --host 0.0.0.0

Or programmatically:
    from agentguard.proxy.app import create_proxy_app
    app = create_proxy_app()
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

# Load environment-specific defaults first (.env.dev / .env.production), then
# let .env (gitignored, machine-local secrets) override individual values —
# same pattern as api/main.py. Without this, a bare `uvicorn
# agentguard.proxy.app:app` run (not through docker-compose) silently misses
# DATABASE_URL and falls back to an in-memory event ledger, so every action
# it intercepts is invisible to the dashboard (which reads api/main.py's
# Postgres-backed ledger) — this is what happened during the 2026-08-11
# dogfood session; see project memory.
_env_name = os.getenv("ENV", "development")
_repo_root = Path(__file__).parent.parent.parent
load_dotenv(_repo_root / f".env.{_env_name}", override=False)
load_dotenv(_repo_root / ".env", override=True)

import structlog
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from agentguard.proxy.middleware import FailClosedMiddleware, RequestIDMiddleware
from agentguard.proxy.router_admin import router as admin_router
from agentguard.proxy.router_anthropic import router as anthropic_router
from agentguard.proxy.router_openai import router as openai_router
from agentguard.telemetry.logger import configure_logging

logger = structlog.get_logger(__name__)


def _validate_credentials(guardrail: Any, interceptor: Any) -> None:
    """
    Fail loudly at startup if a configured analysis backend has no usable API
    key, instead of constructing successfully and only discovering this per-
    request as an opaque 'analyzer_unavailable: TypeError' deep in the call
    stack — which fail-closes every single action on every request until
    someone thinks to grep the logs. (anthropic.AsyncAnthropic and
    openai.AsyncOpenAI both accept api_key=None at construction without
    raising — the failure only surfaces on the first real call.)
    """
    problems: list[str] = []

    deep = getattr(guardrail, "_deep", None) if guardrail is not None else None
    if deep is not None and not getattr(getattr(deep, "_client", None), "api_key", None):
        problems.append(
            "Guardrail deep_analysis is enabled but has no usable ANTHROPIC_API_KEY. "
            "Set it, or disable deep analysis via "
            "AGENTGUARD_PROXY_GUARDRAIL_DEEP_ANALYSIS=false "
            "(not recommended — regex-only guardrail coverage is prone to false "
            "positives on legitimate security-related text)."
        )

    analyzer_backend = getattr(getattr(interceptor, "_analyzer", None), "_backend", None)
    if analyzer_backend is not None and not getattr(getattr(analyzer_backend, "_client", None), "api_key", None):
        provider = getattr(analyzer_backend, "provider", "unknown")
        problems.append(
            f"Intent analyzer backend '{provider}' has no usable API key. Set the "
            "matching provider env var (e.g. ANTHROPIC_API_KEY, OPENAI_API_KEY), or "
            "configure a local provider via AGENTGUARD_ANALYZER=ollama."
        )

    if problems:
        for detail in problems:
            logger.critical("proxy_startup_credential_check_failed", detail=detail)
        raise RuntimeError(
            "AgentGuard proxy startup aborted — starting anyway would silently "
            "fail-closed every request:\n  - " + "\n  - ".join(problems)
        )


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Warm up singletons at startup and clean up on shutdown."""
    from agentguard.proxy.dependencies import (
        get_http_client,
        get_proxy_config,
        get_proxy_guardrail,
        get_proxy_interceptor,
    )
    config = get_proxy_config()
    configure_logging(log_level=config.log_level, json_logs=False)
    logger.info("proxy_starting", port=config.port)

    # Pre-warm the guardrail (loads regex patterns into memory)
    guardrail = get_proxy_guardrail()
    # Pre-warm the interceptor (constructs the intent analyzer backend)
    interceptor = get_proxy_interceptor()
    # Pre-warm the HTTP client (establishes connection pool)
    get_http_client()

    _validate_credentials(guardrail, interceptor)

    logger.info("proxy_ready", port=config.port)
    yield

    # Graceful shutdown: close the HTTP client connection pool
    client = get_http_client()
    await client.aclose()
    logger.info("proxy_stopped")


def create_proxy_app() -> FastAPI:
    """Create and configure the LLM API Proxy FastAPI application."""
    from agentguard.proxy.dependencies import get_proxy_config
    config = get_proxy_config()

    app = FastAPI(
        title="AgentGuard LLM API Proxy",
        description=(
            "Transparent proxy for OpenAI and Anthropic APIs. "
            "Intercepts all LLM traffic for inbound scanning and tool call enforcement."
        ),
        version="1.0.0",
        lifespan=_lifespan,
        docs_url="/docs",
        redoc_url=None,
    )

    # Middleware — order matters: RequestID first, then FailClosed wraps everything
    app.add_middleware(FailClosedMiddleware, fail_closed=config.fail_closed)
    app.add_middleware(RequestIDMiddleware)

    # Routes
    app.include_router(openai_router)
    app.include_router(anthropic_router)
    app.include_router(admin_router)

    @app.get("/health")
    async def health() -> JSONResponse:
        return JSONResponse({"status": "ok", "service": "agentguard-proxy"})

    @app.get("/")
    async def root() -> JSONResponse:
        return JSONResponse({
            "service": "AgentGuard LLM API Proxy",
            "endpoints": ["/v1/chat/completions", "/v1/messages"],
            "health": "/health",
        })

    return app


# Module-level app instance for uvicorn
app = create_proxy_app()
