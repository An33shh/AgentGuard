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

from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from agentguard.proxy.middleware import FailClosedMiddleware, RequestIDMiddleware
from agentguard.proxy.router_anthropic import router as anthropic_router
from agentguard.proxy.router_openai import router as openai_router
from agentguard.telemetry.logger import configure_logging

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Warm up singletons at startup and clean up on shutdown."""
    from agentguard.proxy.dependencies import (
        get_http_client,
        get_proxy_config,
        get_proxy_guardrail,
    )
    config = get_proxy_config()
    configure_logging(log_level=config.log_level, json_logs=False)
    logger.info("proxy_starting", port=config.port)

    # Pre-warm the guardrail (loads regex patterns into memory)
    get_proxy_guardrail()
    # Pre-warm the HTTP client (establishes connection pool)
    get_http_client()

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
