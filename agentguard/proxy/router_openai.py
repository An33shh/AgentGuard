"""
OpenAI-compatible proxy router.

Intercepts POST /v1/chat/completions, runs the AgentGuard proxy pipeline,
and forwards to the real OpenAI API (or any OpenAI-compatible endpoint).
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from agentguard.auth.rate_limiter import get_rate_limiter
from agentguard.proxy.dependencies import (
    extract_request_context,
    get_http_client,
    get_proxy_config,
    get_proxy_guardrail,
    get_proxy_interceptor,
)
from agentguard.proxy.format_handler import OpenAIFormatHandler
from agentguard.proxy.pipeline import ProxyPipeline

logger = structlog.get_logger(__name__)
router = APIRouter()

_handler = OpenAIFormatHandler()

# Module-level pipeline singleton — stateless, heavy deps pulled from lru_cache
_pipeline: ProxyPipeline | None = None


def _get_pipeline() -> ProxyPipeline:
    global _pipeline
    if _pipeline is None:
        config = get_proxy_config()
        _pipeline = ProxyPipeline(
            interceptor=get_proxy_interceptor(),
            guardrail=get_proxy_guardrail(),
            scan_inbound=config.scan_inbound,
            intercept_tool_calls=config.intercept_tool_calls,
        )
    return _pipeline


@router.post("/v1/chat/completions")
async def proxy_chat_completions(request: Request) -> JSONResponse:
    """Proxy POST /v1/chat/completions with AgentGuard interception."""
    config = get_proxy_config()
    body = await request.json()

    # Reject streaming requests with a clear error instead of silently coercing
    if body.get("stream") is True:
        return JSONResponse(
            status_code=400,
            content={"error": {
                "message": "AgentGuard proxy does not support streaming (stream=true). Set stream=false.",
                "type": "invalid_request_error",
                "code": "streaming_not_supported",
            }},
        )

    # Rate limit by session_id derived from auth header
    context = extract_request_context(request, config)
    limiter = get_rate_limiter()
    if not await limiter.is_allowed(context.session_id):
        return JSONResponse(
            status_code=429,
            content={"error": {
                "message": "AgentGuard proxy rate limit exceeded.",
                "type": "rate_limit_error",
                "code": "rate_limit_exceeded",
            }},
        )

    # Build upstream headers — pass through auth, strip hop-by-hop headers
    upstream_headers = _build_upstream_headers(request)

    pipeline = _get_pipeline()
    client = get_http_client()

    async def upstream_call(normalized_body: dict[str, Any], headers: dict[str, str]) -> tuple[dict, int]:
        url = f"{config.openai_base_url}/v1/chat/completions"
        response = await client.post(url, json=normalized_body, headers=headers)
        return response.json(), response.status_code

    response_body, status_code = await pipeline.handle_request(
        body=body,
        upstream_headers=upstream_headers,
        handler=_handler,
        context=context,
        upstream_call=upstream_call,
    )
    return JSONResponse(content=response_body, status_code=status_code)


def _build_upstream_headers(request: Request) -> dict[str, str]:
    """Extract headers to forward upstream, removing proxy-specific ones."""
    _strip = {
        "host", "content-length", "transfer-encoding", "connection",
        "x-agentguard-goal", "x-agentguard-session", "x-agentguard-agentid",
    }
    return {
        k: v for k, v in request.headers.items()
        if k.lower() not in _strip
    }
