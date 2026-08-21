"""
Anthropic Messages API proxy router.

Intercepts POST /v1/messages, runs the AgentGuard proxy pipeline,
and forwards to the real Anthropic API.
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from agentguard.auth.rate_limiter import get_rate_limiter
from agentguard.proxy.dependencies import (
    build_upstream_headers,
    extract_request_context,
    get_http_client,
    get_proxy_config,
    get_proxy_guardrail,
    get_proxy_interceptor,
)
from agentguard.proxy.format_handler import AnthropicFormatHandler
from agentguard.proxy.pipeline import ProxyPipeline, StreamingProxyPipeline

logger = structlog.get_logger(__name__)
router = APIRouter()

_handler = AnthropicFormatHandler()

# Module-level pipeline singletons — stateless, heavy deps pulled from lru_cache
_pipeline: ProxyPipeline | None = None
_streaming_pipeline: StreamingProxyPipeline | None = None


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


def _get_streaming_pipeline() -> StreamingProxyPipeline:
    global _streaming_pipeline
    if _streaming_pipeline is None:
        config = get_proxy_config()
        _streaming_pipeline = StreamingProxyPipeline(
            interceptor=get_proxy_interceptor(),
            guardrail=get_proxy_guardrail(),
            scan_inbound=config.scan_inbound,
            intercept_tool_calls=config.intercept_tool_calls,
        )
    return _streaming_pipeline


@router.post("/v1/messages", response_model=None)
async def proxy_messages(request: Request) -> Response:
    """Proxy POST /v1/messages with AgentGuard interception."""
    config = get_proxy_config()
    body = await request.json()

    # Rate limit by session_id derived from auth header — happens before the
    # stream/non-stream branch, so a rate-limited streaming request still
    # gets a clean buffered 429 and never opens an SSE connection at all.
    context = extract_request_context(request, config, body=body, handler=_handler)
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

    upstream_headers = build_upstream_headers(request, config)

    if body.get("stream") is True:
        return _handle_streaming(body, upstream_headers, context, config)

    pipeline = _get_pipeline()
    client = get_http_client()

    async def upstream_call(normalized_body: dict[str, Any], headers: dict[str, str]) -> tuple[dict, int]:
        url = f"{config.anthropic_base_url}/v1/messages"
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


def _handle_streaming(
    body: dict[str, Any],
    upstream_headers: dict[str, str],
    context: Any,
    config: Any,
) -> StreamingResponse:
    pipeline = _get_streaming_pipeline()
    client = get_http_client()

    def upstream_stream_call(normalized_body: dict[str, Any], headers: dict[str, str]):
        url = f"{config.anthropic_base_url}/v1/messages"
        return client.stream("POST", url, json=normalized_body, headers=headers)

    generator = pipeline.handle_stream(
        body=body,
        upstream_headers=upstream_headers,
        handler=_handler,
        context=context,
        upstream_stream_call=upstream_stream_call,
    )
    return StreamingResponse(generator, media_type="text/event-stream")


