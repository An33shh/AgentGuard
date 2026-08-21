"""
ProxyPipeline — core orchestrator for the LLM API Proxy.

Flow:
  1. Extract inbound text segments from the request.
  2. Scan each segment with PromptGuardrail (fast, zero-LLM-cost in enforce mode).
  3. If any segment is BLOCK → return blocked response immediately.
  4. Forward the (normalized) request to the real LLM.
  5. Extract tool calls from the LLM response.
  6. Run each tool call concurrently through AgentGuard's Interceptor pipeline.
  7. Build and return the final response:
     a. All allowed  → return original response unchanged.
     b. Some blocked → return modified response with blocked calls removed + explanation injected.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager
from typing import Any

import httpx
import structlog

from agentguard.core.models import Decision, ProvenanceSourceType, ProvenanceTag
from agentguard.guardrail.models import ContextType, GuardrailVerdict
from agentguard.proxy.format_handler import (
    LLMFormatHandler,
    StreamBlockKind,
    StreamingCapableHandler,
)
from agentguard.proxy.models import (
    ProxyInterceptionResult,
    ProxyRequestContext,
)
from agentguard.proxy.sse import SSEEvent, encode_sse_event, iter_sse_events

if False:  # TYPE_CHECKING without import
    from agentguard.guardrail.guardrail import PromptGuardrail
    from agentguard.interceptor.interceptor import Interceptor

logger = structlog.get_logger(__name__)


def _context_type_for_role(role: str) -> ContextType:
    """
    Map a message's role to the guardrail's risk context.

    'assistant' text is the model's own trusted output, not attacker-
    controlled input — it must NOT share TOOL_RESPONSE's higher-risk
    bucket (that's reserved for actual tool_result content, which really
    is a deliberate attacker vector). Conflating the two meant the
    guardrail scanned the model's own prior turns — which routinely
    discuss security terminology like "jailbreak" while doing security
    work — as if they were untrusted tool output, and via replayed
    conversation history that recurs on every subsequent request, a
    single false positive there permanently blocked the rest of the
    session.
    """
    if role == "user":
        return ContextType.USER_INPUT
    if role in ("system", "assistant"):
        return ContextType.SYSTEM
    # "tool_result" (Anthropic) / "tool" (OpenAI) and anything else is
    # actual tool output — the real, deliberately-targeted injection vector.
    return ContextType.TOOL_RESPONSE


async def _scan_inbound_texts(
    guardrail: Any,
    body: dict[str, Any],
    handler: LLMFormatHandler,
    context: ProxyRequestContext,
) -> str | None:
    """
    Scan all inbound text segments.

    Returns the block reason string if any segment should be blocked,
    or None if everything is clean. Module-level so both ProxyPipeline and
    StreamingProxyPipeline share the identical inbound-scan behavior.
    """
    targets = handler.extract_inbound_texts(body)
    if not targets:
        return None

    tasks = [
        guardrail.scan(t.text, _context_type_for_role(t.role))
        for t in targets
    ]
    results = await asyncio.gather(*tasks)

    for target, result in zip(targets, results):
        if result.verdict == GuardrailVerdict.BLOCK:
            detections = [d.pattern_name for d in result.detections]
            return (
                f"Inbound {target.role!r} message (index={target.message_index}) "
                f"contains a security threat: {detections}"
            )

    return None


def _provenance_tags(context: ProxyRequestContext) -> list[ProvenanceTag]:
    tags = [
        ProvenanceTag(
            source_type=ProvenanceSourceType.SYSTEM,
            label="llm_proxy",
            value=context.agent_goal[:80],
        )
    ]
    if context.agent_id:
        # Self-asserted by the client via X-AgentGuard-AgentId, never
        # verified — see the enforcement note in _intercept_single below.
        # Kept for audit visibility only; do not treat as identity.
        tags.append(ProvenanceTag(
            source_type=ProvenanceSourceType.SYSTEM,
            label="llm_proxy_claimed_agent_id_unverified",
            value=context.agent_id[:80],
        ))
    if context.fingerprint_mismatch is not None:
        m = context.fingerprint_mismatch
        tags.append(ProvenanceTag(
            source_type=ProvenanceSourceType.SYSTEM,
            label="llm_proxy_framework_signal_mismatch",
            value=f"UA claims '{m.claimed_framework}', tools missing {sorted(m.missing_markers)}"[:80],
        ))
    return tags


async def _intercept_single(
    interceptor: Any,
    tool_call: Any,
    context: ProxyRequestContext,
) -> ProxyInterceptionResult:
    """Run one tool call through the Interceptor. Module-level so both
    ProxyPipeline and StreamingProxyPipeline share identical fail-closed
    behavior on unexpected errors."""
    raw_payload = {
        "tool_name": tool_call.name,
        "parameters": tool_call.arguments,
    }
    try:
        decision, event = await interceptor.intercept(
            raw_payload=raw_payload,
            agent_goal=context.agent_goal,
            session_id=context.session_id,
            # agent_id intentionally NOT forwarded. X-AgentGuard-AgentId is
            # an unauthenticated, self-asserted client header — forwarding
            # it into Interceptor.intercept()'s agent_id param flips
            # is_registered=True (interceptor.py), which skips the
            # deny_unregistered_tools ABAC rule entirely (policy/engine.py).
            # Until the proxy has a real, operator-vetted agent-
            # registration mechanism, a claimed agent_id is carried only as
            # an unverified provenance tag (_provenance_tags) — never as
            # enforcement-relevant identity.
            provenance_tags=_provenance_tags(context),
            framework=context.framework,
            correlation_id=context.correlation_id,
            initiating_principal=context.initiating_principal,
        )
        allowed = decision != Decision.BLOCK
        reason = event.assessment.reason if not allowed else ""
        risk_score = event.assessment.risk_score
    except Exception as exc:
        logger.error("proxy_intercept_error", tool=tool_call.name, error=str(exc))
        # Fail closed — unknown error → block
        allowed = False
        reason = f"Internal error during interception: {type(exc).__name__}"
        risk_score = 1.0

    return ProxyInterceptionResult(
        tool_call=tool_call,
        allowed=allowed,
        reason=reason,
        risk_score=risk_score,
    )


class ProxyPipeline:
    """
    Orchestrates inbound scanning + tool call interception for a single
    proxied LLM request.
    """

    def __init__(
        self,
        interceptor: Interceptor,
        guardrail: PromptGuardrail | None,
        scan_inbound: bool = True,
        intercept_tool_calls: bool = True,
    ) -> None:
        self._interceptor = interceptor
        self._guardrail = guardrail
        self._scan_inbound = scan_inbound
        self._intercept_tool_calls = intercept_tool_calls

    async def handle_request(
        self,
        body: dict[str, Any],
        upstream_headers: dict[str, str],
        handler: LLMFormatHandler,
        context: ProxyRequestContext,
        upstream_call: Any,  # async callable(normalized_body, headers) -> (response_body, status)
    ) -> tuple[dict[str, Any], int]:
        """
        Full proxy pipeline.

        Returns (response_body, status_code).
        """
        # ---- Step 1+2: Inbound scan ----------------------------------------
        if self._scan_inbound and self._guardrail is not None:
            block_reason = await self._scan_inbound_texts(body, handler, context)
            if block_reason:
                model = body.get("model", "unknown")
                blocked_body = handler.build_inbound_block_response(block_reason, model)
                logger.warning(
                    "proxy_inbound_blocked",
                    session_id=context.session_id,
                    agent_goal=context.agent_goal[:80],
                    reason=block_reason,
                )
                return blocked_body, 200  # 200 so the agent loop doesn't crash

        # ---- Step 3: Normalize + forward -----------------------------------
        normalized = handler.normalize_request(body)
        response_body, status_code = await upstream_call(normalized, upstream_headers)

        if status_code != 200:
            return response_body, status_code

        # ---- Step 4+5: Tool call interception ------------------------------
        if self._intercept_tool_calls:
            tool_calls = handler.extract_tool_calls(response_body)
            if tool_calls:
                results = await self._intercept_tool_calls_concurrent(tool_calls, context)
                blocked = [r for r in results if not r.allowed]
                if blocked:
                    allowed = [r for r in results if r.allowed]
                    response_body = handler.build_blocked_response(response_body, blocked)
                    logger.warning(
                        "proxy_tool_calls_blocked",
                        session_id=context.session_id,
                        blocked=[r.tool_call.name for r in blocked],
                        allowed=[r.tool_call.name for r in allowed],
                    )

        return response_body, status_code

    async def _scan_inbound_texts(
        self,
        body: dict[str, Any],
        handler: LLMFormatHandler,
        context: ProxyRequestContext,
    ) -> str | None:
        """Delegates to the module-level helper shared with StreamingProxyPipeline."""
        return await _scan_inbound_texts(self._guardrail, body, handler, context)

    async def _intercept_tool_calls_concurrent(
        self,
        tool_calls: list,
        context: ProxyRequestContext,
    ) -> list[ProxyInterceptionResult]:
        """Run all tool calls through the Interceptor concurrently."""
        tasks = [
            self._intercept_single(tc, context)
            for tc in tool_calls
        ]
        return await asyncio.gather(*tasks)

    async def _intercept_single(
        self,
        tool_call: Any,
        context: ProxyRequestContext,
    ) -> ProxyInterceptionResult:
        """Delegates to the module-level helper shared with StreamingProxyPipeline."""
        return await _intercept_single(self._interceptor, tool_call, context)


class StreamingProxyPipeline:
    """
    Streaming counterpart to ProxyPipeline.

    Reuses the exact same inbound-scan (_scan_inbound_texts) and tool-call-
    interception (_intercept_single) primitives ProxyPipeline uses — the only
    new logic here is the SSE buffer/pass-through state machine. Ordinary text
    streams to the client in real time, byte-for-byte; only tool-call blocks
    are buffered, and only for as long as it takes that one block to finish
    arriving from upstream.

    Provider-agnostic: operates entirely in terms of SSEEvent/StreamEventInfo.
    All provider wire-format knowledge lives in the handler
    (StreamingCapableHandler), never here.
    """

    def __init__(
        self,
        interceptor: Any,
        guardrail: Any | None,
        scan_inbound: bool = True,
        intercept_tool_calls: bool = True,
    ) -> None:
        self._interceptor = interceptor
        self._guardrail = guardrail
        self._scan_inbound = scan_inbound
        self._intercept_tool_calls = intercept_tool_calls

    async def handle_stream(
        self,
        body: dict[str, Any],
        upstream_headers: dict[str, str],
        handler: LLMFormatHandler,  # also a StreamingCapableHandler
        context: ProxyRequestContext,
        upstream_stream_call: Callable[[dict[str, Any], dict[str, str]], AbstractAsyncContextManager[httpx.Response]],
    ) -> AsyncIterator[bytes]:
        """
        Async-generator entry point, handed straight to FastAPI's
        StreamingResponse(generator, media_type="text/event-stream").

        Never lets an exception propagate once iteration has begun: on any
        failure (upstream connect error, malformed stream, unexpected proxy
        bug) it emits a single in-band, well-formed error response and closes
        cleanly, rather than hanging the connection or crashing the ASGI app.
        This mirrors the existing non-streaming inbound-block path, which
        also returns a clean 200 with an explanation rather than an HTTP
        error, "so the agent loop doesn't crash" (see build_inbound_block_response
        usage in ProxyPipeline.handle_request).
        """
        assert isinstance(handler, StreamingCapableHandler)
        model = body.get("model", "unknown")
        try:
            # ---- Step 1: inbound scan (identical to ProxyPipeline) --------
            if self._scan_inbound and self._guardrail is not None:
                block_reason = await _scan_inbound_texts(self._guardrail, body, handler, context)
                if block_reason:
                    logger.warning(
                        "proxy_inbound_blocked",
                        session_id=context.session_id,
                        agent_goal=context.agent_goal[:80],
                        reason=block_reason,
                        streaming=True,
                    )
                    blocked_body = handler.build_inbound_block_response(block_reason, model)
                    for event in handler.wrap_as_sse_stream(blocked_body):
                        yield encode_sse_event(event)
                    return

            # ---- Step 2: normalize + open upstream stream ------------------
            normalized = handler.normalize_stream_request(body)
            async with upstream_stream_call(normalized, upstream_headers) as response:
                if response.status_code != 200:
                    raw = await response.aread()
                    logger.warning(
                        "proxy_stream_upstream_error",
                        status=response.status_code,
                        session_id=context.session_id,
                    )
                    error_body = handler.build_inbound_block_response(
                        f"upstream returned HTTP {response.status_code}: {raw[:200]!r}", model,
                    )
                    for event in handler.wrap_as_sse_stream(error_body):
                        yield encode_sse_event(event)
                    return

                async for chunk in self._stream_with_interception(response, handler, context):
                    yield chunk

        except Exception as exc:
            logger.error("proxy_stream_error", error=str(exc), error_type=type(exc).__name__, session_id=context.session_id)
            error_body = handler.build_inbound_block_response(
                f"proxy error: {type(exc).__name__}", model,
            )
            try:
                for event in handler.wrap_as_sse_stream(error_body):
                    yield encode_sse_event(event)
            except Exception:
                # Even the fallback error-wrapping failed — nothing left to do
                # but stop the generator; the client sees a clean stream close.
                return

    async def _resolve_tool_block(
        self,
        handler: StreamingCapableHandler,
        index: int,
        open_raw: dict[int, list[SSEEvent]],
        open_meta: dict[int, dict[str, Any]],
        context: ProxyRequestContext,
    ) -> tuple[list[bytes], bool]:
        """Assemble, intercept, and encode the wire bytes for one closed
        tool-call block. Returns (encoded_events, allowed) — the caller
        yields the events and folds `allowed` into any_blocked/
        any_allowed_tool_use. Shared by the BLOCK_STOP path (Anthropic:
        each block closes individually) and the MESSAGE_DELTA path
        (OpenAI: every open block closes together, see this class's
        docstring and format_handler.py's module docstring)."""
        meta = open_meta[index]
        tool_call = handler.assemble_tool_call(
            index, meta["tool_call_id"], meta["tool_name"], "".join(meta["fragments"]),
        )
        if self._intercept_tool_calls:
            result = await _intercept_single(self._interceptor, tool_call, context)
        else:
            result = ProxyInterceptionResult(tool_call=tool_call, allowed=True)

        if result.allowed:
            return [encode_sse_event(e) for e in open_raw[index]], True

        logger.warning(
            "proxy_stream_tool_call_blocked",
            tool=tool_call.name,
            reason=result.reason,
            session_id=context.session_id,
        )
        blocked_events = [
            encode_sse_event(e) for e in handler.build_blocked_stream_events(index, tool_call, result.reason)
        ]
        return blocked_events, False

    async def _stream_with_interception(
        self,
        response: httpx.Response,
        handler: StreamingCapableHandler,
        context: ProxyRequestContext,
    ) -> AsyncIterator[bytes]:
        """The actual buffer/intercept/flush state machine, isolated from the
        outer error-handling wrapper for readability."""
        # Per-request state — safe, this method is called once per request,
        # never shared across concurrent streams (unlike the handler, which
        # is a shared singleton and must stay stateless).
        open_raw: dict[int, list[SSEEvent]] = {}
        open_meta: dict[int, dict[str, Any]] = {}
        any_blocked = False
        any_allowed_tool_use = False

        async for raw_event in iter_sse_events(response):
            info = handler.classify_stream_event(raw_event)

            if info.kind in (StreamBlockKind.PASSTHROUGH, StreamBlockKind.PING):
                yield encode_sse_event(raw_event)
                continue

            if info.kind == StreamBlockKind.TOOL_BLOCK_START:
                if info.block_index is not None:
                    open_raw[info.block_index] = [raw_event]
                    open_meta[info.block_index] = {
                        "tool_call_id": info.tool_call_id or "",
                        "tool_name": info.tool_name or "unknown",
                        "fragments": [],
                    }
                else:
                    # Malformed/non-standard upstream — a tool_use block
                    # start with no index at all. Can't be buffered (nothing
                    # to key it by), so forward defensively rather than
                    # silently drop it, matching the same posture used below
                    # for a delta/stop event referencing a block we never
                    # saw start.
                    logger.warning("proxy_stream_tool_block_start_missing_index")
                    yield encode_sse_event(raw_event)
                continue

            if info.kind == StreamBlockKind.TOOL_BLOCK_DELTA:
                if info.block_index is None:
                    logger.warning("proxy_stream_delta_missing_index")
                    yield encode_sse_event(raw_event)
                    continue
                if info.block_index not in open_raw:
                    # Implicit start: a provider with no distinct "block
                    # start" event (OpenAI) signals a new tool call purely
                    # by a delta carrying a not-yet-seen index — the first
                    # such delta IS the start. tool_call_id/tool_name may
                    # still be None here (some OpenAI-compatible providers
                    # send them in a later delta for the same index, see
                    # format_handler.py's module docstring); default the
                    # same way TOOL_BLOCK_START does above, and fill them in
                    # below if/when they arrive. Also a defensive upgrade
                    # for any provider: a delta for a block whose explicit
                    # start event was somehow missed now gets buffered
                    # instead of leaked unbuffered.
                    open_raw[info.block_index] = []
                    open_meta[info.block_index] = {
                        "tool_call_id": info.tool_call_id or "",
                        "tool_name": info.tool_name or "unknown",
                        "fragments": [],
                    }
                open_raw[info.block_index].append(raw_event)
                meta = open_meta[info.block_index]
                if info.tool_call_id:
                    meta["tool_call_id"] = info.tool_call_id
                if info.tool_name:
                    meta["tool_name"] = info.tool_name
                meta["fragments"].append(info.json_fragment or "")
                continue

            if info.kind == StreamBlockKind.BLOCK_STOP:
                index = info.block_index
                if index is not None and index in open_raw:
                    open_raw[index].append(raw_event)
                    events, allowed = await self._resolve_tool_block(handler, index, open_raw, open_meta, context)
                    for encoded in events:
                        yield encoded
                    if allowed:
                        any_allowed_tool_use = True
                    else:
                        any_blocked = True
                    del open_raw[index]
                    del open_meta[index]
                else:
                    # Stop event for a block we never buffered (an ordinary
                    # text block closing) — plain passthrough.
                    yield encode_sse_event(raw_event)
                continue

            if info.kind == StreamBlockKind.MESSAGE_DELTA:
                # Resolve any tool-call blocks still open when the
                # response-level stop/finish signal arrives. This is a
                # no-op for Anthropic, which explicitly closes each block
                # via its own BLOCK_STOP event before MESSAGE_DELTA ever
                # arrives (open_raw should already be empty here). It's
                # load-bearing for OpenAI: there is no per-block close
                # event at all, so every open tool call actually gets
                # resolved right here, all at once — see
                # format_handler.py's module docstring.
                for index in sorted(open_raw.keys()):
                    events, allowed = await self._resolve_tool_block(handler, index, open_raw, open_meta, context)
                    for encoded in events:
                        yield encoded
                    if allowed:
                        any_allowed_tool_use = True
                    else:
                        any_blocked = True
                open_raw.clear()
                open_meta.clear()

                # Only rewrite stop_reason when EVERY tool call in this
                # response was blocked. If at least one was allowed, the
                # client still needs stop_reason="tool_use" to know it must
                # execute that allowed call — rewriting it to "end_turn"
                # here would silently strand a legitimately-allowed tool
                # call the client would otherwise have run.
                if any_blocked and not any_allowed_tool_use:
                    yield encode_sse_event(handler.patch_message_delta_after_block(raw_event))
                else:
                    yield encode_sse_event(raw_event)
                continue

            if info.kind == StreamBlockKind.STREAM_END:
                yield encode_sse_event(raw_event)
                break

        # Fail-closed safety net: if the upstream stream ended (via STREAM_END
        # or the connection simply closing) while a tool-call block was still
        # open, that tool call was never scanned — never leak it to the
        # client under any circumstances.
        if open_raw:
            logger.error(
                "proxy_stream_truncated_tool_block",
                open_blocks=list(open_raw.keys()),
                session_id=context.session_id,
            )
