"""
LLM format handlers for OpenAI and Anthropic API schemas.

Each handler translates between the provider's wire format and AgentGuard's
internal proxy models, and back.

Adding a new provider: implement LLMFormatHandler's 6 methods (request/
response translation, plus tool-name extraction for framework
fingerprinting) and, for real-time streaming support, also implement
StreamingCapableHandler's 6 methods (SSE event classification, tool-call
assembly, blocked-block synthesis, post-block stop-reason correction,
non-streaming-to-SSE wrapping, and the stream-mode request normalizer). Add
one router file modeled on router_anthropic.py and register it in app.py.
Nothing in sse.py or StreamingProxyPipeline (pipeline.py) needs to change —
that logic is fully provider-agnostic.

NOTE: there is currently no automatic fallback for a stream:true request
against a handler that only implements LLMFormatHandler, not
StreamingCapableHandler — StreamingProxyPipeline.handle_stream() asserts
isinstance(handler, StreamingCapableHandler) up front (pipeline.py) and
raises if that doesn't hold. A router for such a handler must reject
stream:true itself rather than routing into StreamingProxyPipeline and
hitting that assert (both OpenAIFormatHandler and AnthropicFormatHandler now
implement StreamingCapableHandler, so this only matters for a future
provider that doesn't yet). wrap_as_sse_stream() below is used elsewhere in
this pipeline for synthesizing synthetic SSE responses (inbound-block/error
messages) mid-stream, not as a buffer-then-wrap fallback for a
non-streaming-capable handler.

OpenAI's Chat Completions streaming format differs structurally from
Anthropic's in two ways worth knowing before touching OpenAIFormatHandler's
StreamingCapableHandler methods:

1. No per-block "this tool call is done" event. Anthropic sends an explicit
   content_block_stop per block; OpenAI has nothing equivalent — every tool
   call in the response closes simultaneously, signaled only by the single
   finish_reason chunk at the very end. classify_stream_event() therefore
   never emits TOOL_BLOCK_START for OpenAI (there's nothing to distinguish
   it from a later delta without cross-event memory, which the classifier
   isn't allowed to keep — see StreamingCapableHandler's docstring); every
   tool_calls-bearing chunk is classified as TOOL_BLOCK_DELTA, and
   StreamingProxyPipeline treats the first delta for a not-yet-seen index as
   an implicit start. Resolving every still-open block when MESSAGE_DELTA
   arrives (also added for this) is what actually closes OpenAI's tool
   calls; it's a no-op for Anthropic, which should have already closed its
   blocks via content_block_stop by then.
2. tool_calls[].id/function.name aren't guaranteed to arrive in the same
   chunk as the first argument fragment for that index — confirmed against
   real-world OpenAI-compatible gateway behavior, not just the spec's
   wording. TOOL_BLOCK_DELTA's tool_call_id/tool_name fields (unused by
   Anthropic, which always has both at TOOL_BLOCK_START) let a later delta
   fill them in once they do arrive.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any

import structlog

from agentguard.proxy.models import (
    ProxyInboundScanTarget,
    ProxyInterceptionResult,
    ProxyToolCall,
)
from agentguard.proxy.sse import SSEEvent

logger = structlog.get_logger(__name__)


class LLMFormatHandler(ABC):
    """Abstract base class for provider-specific format translation."""

    @abstractmethod
    def extract_inbound_texts(self, body: dict[str, Any]) -> list[ProxyInboundScanTarget]:
        """Extract all text segments from the request body for inbound scanning."""

    @abstractmethod
    def extract_tool_calls(self, response_body: dict[str, Any]) -> list[ProxyToolCall]:
        """Extract tool calls from an LLM response body."""

    @abstractmethod
    def extract_tool_names(self, body: dict[str, Any]) -> list[str]:
        """
        Extract declared tool/function names from the request body's tools
        array, for framework fingerprinting (agentguard.proxy.fingerprint).
        Return [] if absent — never raises on a malformed tools array.
        """

    @abstractmethod
    def build_blocked_response(
        self,
        original_response: dict[str, Any],
        blocked_results: list[ProxyInterceptionResult],
        allowed_results: list[ProxyInterceptionResult],
    ) -> dict[str, Any]:
        """
        Return a modified response with blocked tool calls removed and a
        text explanation injected so the agent loop knows why.
        """

    @abstractmethod
    def build_inbound_block_response(self, reason: str, model: str) -> dict[str, Any]:
        """
        Return a complete error response body when inbound scanning blocks the request.
        """

    @abstractmethod
    def normalize_request(self, body: dict[str, Any]) -> dict[str, Any]:
        """
        Normalize the request before forwarding upstream.

        Phase 1: force stream=false so the pipeline doesn't need SSE buffering.
        """


class StreamBlockKind(str, Enum):
    """How StreamingProxyPipeline's buffer state machine should treat one
    classified upstream SSE event."""

    PASSTHROUGH = "passthrough"  # forward this raw event to the client immediately, unmodified
    PING = "ping"                # keep-alive; forward immediately, never buffer
    TOOL_BLOCK_START = "tool_block_start"
    TOOL_BLOCK_DELTA = "tool_block_delta"
    # A content-block/output-item "stop" event. Ambiguous in isolation — the
    # pipeline (which owns per-request open-block state) decides whether this
    # closes a tool call it was buffering (real end) or an ordinary text block
    # it never buffered (plain passthrough). Kept out of the per-event
    # classifier so the classifier stays stateless and safe to share across
    # concurrent requests.
    BLOCK_STOP = "block_stop"
    # Carries the response-level stop/finish reason (Anthropic's
    # message_delta, OpenAI's final chunk). Must be classified distinctly
    # from PASSTHROUGH: if an earlier block in this same response was
    # replaced by a blocked-tool-call substitution, this event needs
    # correcting too — otherwise it can still claim e.g. stop_reason=
    # "tool_use" pointing at a tool_use block that no longer exists,
    # which is exactly what leaves a client unable to resume the agent
    # loop after a block.
    MESSAGE_DELTA = "message_delta"
    STREAM_END = "stream_end"    # terminal event (message_stop / response.completed)


@dataclass
class StreamEventInfo:
    kind: StreamBlockKind
    block_index: int | None = None     # provider's own block/output-item index
    tool_name: str | None = None       # set on TOOL_BLOCK_START
    tool_call_id: str | None = None    # set on TOOL_BLOCK_START
    json_fragment: str | None = None   # set on TOOL_BLOCK_DELTA — partial JSON for this delta


class StreamingCapableHandler(ABC):
    """
    Mixin adding SSE streaming support to an LLMFormatHandler. A
    streaming-capable provider implements both, e.g.:
    `class AnthropicFormatHandler(LLMFormatHandler, StreamingCapableHandler)`.
    """

    @abstractmethod
    def classify_stream_event(self, event: SSEEvent) -> StreamEventInfo:
        """
        Classify one raw upstream SSEEvent. Must never raise on an
        unrecognized/malformed event — classify as PASSTHROUGH instead, so
        the proxy degrades gracefully (forwards unknown events untouched)
        rather than dropping data or crashing the stream.
        """

    @abstractmethod
    def assemble_tool_call(
        self,
        block_index: int,
        tool_call_id: str,
        tool_name: str,
        accumulated_json: str,
    ) -> ProxyToolCall:
        """
        Build a ProxyToolCall from the fully-accumulated JSON fragments of one
        tool-call block, once its closing event has arrived. Should mirror
        extract_tool_calls()'s json.loads-with-fallback-to-_raw behavior.
        """

    @abstractmethod
    def build_blocked_stream_events(
        self, block_index: int, tool_call: ProxyToolCall, reason: str
    ) -> list[SSEEvent]:
        """
        Synthesize the well-formed replacement SSE event(s) for one blocked
        tool-call block, reusing block_index so later blocks' indices stay
        valid. Must produce a self-contained, spec-shaped block carrying a
        short [AgentGuard] blocked explanation (same message convention as
        build_blocked_response's text injection).
        """

    @abstractmethod
    def patch_message_delta_after_block(self, event: SSEEvent) -> SSEEvent:
        """
        Correct the response-level stop/finish-reason event for a response
        where at least one content block was replaced by a blocked-tool-call
        substitution. Must ensure the corrected event never claims the model
        wants to call a tool it no longer has a matching tool_use block for.
        Returns the event unchanged if it needs no correction.
        """

    @abstractmethod
    def wrap_as_sse_stream(self, response_body: dict[str, Any]) -> list[SSEEvent]:
        """
        Convert a complete non-streaming response body (the same shape
        build_inbound_block_response()/build_blocked_response() produce, or
        any other complete provider response) into the minimal valid SSE
        event sequence for this provider.
        """

    @abstractmethod
    def normalize_stream_request(self, body: dict[str, Any]) -> dict[str, Any]:
        """
        Normalize a request before forwarding upstream for a streaming call
        — the streaming-path counterpart to normalize_request(), which
        always forces stream=False. This forces stream=True instead. Kept
        as a separate method (rather than changing normalize_request) so
        the non-streaming path and its tests are entirely unaffected by
        streaming support.
        """


# ---------------------------------------------------------------------------
# OpenAI Chat Completions  (/v1/chat/completions)
# ---------------------------------------------------------------------------

class OpenAIFormatHandler(LLMFormatHandler, StreamingCapableHandler):
    """Handles OpenAI Chat Completions API format."""

    def extract_inbound_texts(self, body: dict[str, Any]) -> list[ProxyInboundScanTarget]:
        targets: list[ProxyInboundScanTarget] = []
        for i, msg in enumerate(body.get("messages", [])):
            role = msg.get("role", "unknown")
            content = msg.get("content", "")
            if isinstance(content, str) and content.strip():
                targets.append(ProxyInboundScanTarget(text=content, role=role, message_index=i))
            elif isinstance(content, list):
                # Content parts array (vision / tool use messages)
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        text = part.get("text", "")
                        if text.strip():
                            targets.append(ProxyInboundScanTarget(text=text, role=role, message_index=i))
        return targets

    def extract_tool_calls(self, response_body: dict[str, Any]) -> list[ProxyToolCall]:
        tool_calls: list[ProxyToolCall] = []
        for choice in response_body.get("choices", []):
            message = choice.get("message", {})
            for tc in message.get("tool_calls", []) or []:
                fn = tc.get("function", {})
                try:
                    args = json.loads(fn.get("arguments", "{}") or "{}")
                except json.JSONDecodeError:
                    args = {"_raw": fn.get("arguments", "")}
                tool_calls.append(ProxyToolCall(
                    id=tc.get("id", ""),
                    name=fn.get("name", "unknown"),
                    arguments=args,
                    raw=tc,
                ))
        return tool_calls

    def extract_tool_names(self, body: dict[str, Any]) -> list[str]:
        names: list[str] = []
        tools = body.get("tools")
        if not isinstance(tools, list):
            return names
        for t in tools:
            if not isinstance(t, dict):
                continue
            fn = t.get("function")
            name = fn.get("name") if isinstance(fn, dict) else None
            if not (isinstance(name, str) and name):
                name = t.get("name")  # defensive: some OpenAI-compatible gateways flatten this
            if isinstance(name, str) and name:
                names.append(name)
        return names

    def build_blocked_response(
        self,
        original_response: dict[str, Any],
        blocked_results: list[ProxyInterceptionResult],
        allowed_results: list[ProxyInterceptionResult],
    ) -> dict[str, Any]:
        import copy
        response = copy.deepcopy(original_response)

        blocked_ids = {r.tool_call.id for r in blocked_results}
        blocked_names = [r.tool_call.name for r in blocked_results]
        reasons = "; ".join(r.reason for r in blocked_results if r.reason)

        for choice in response.get("choices", []):
            message = choice.get("message", {})
            existing = message.get("tool_calls") or []
            # Keep only allowed tool calls
            message["tool_calls"] = [tc for tc in existing if tc.get("id") not in blocked_ids]
            if not message["tool_calls"]:
                del message["tool_calls"]

            # Inject a text explanation if all tool calls were removed
            if not message.get("tool_calls"):
                explanation = (
                    f"[AgentGuard] The following tool call(s) were blocked by the security policy: "
                    f"{blocked_names}. Reason: {reasons or 'policy violation'}. "
                    "Please adjust your approach and try again without these tools."
                )
                current_content = message.get("content") or ""
                message["content"] = (current_content + "\n\n" + explanation).strip()
                choice["finish_reason"] = "stop"

        return response

    def build_inbound_block_response(self, reason: str, model: str) -> dict[str, Any]:
        return {
            "id": "agentguard-blocked",
            "object": "chat.completion",
            "created": 0,
            "model": model,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": (
                        f"[AgentGuard] This request was blocked by the security policy. "
                        f"Reason: {reason}"
                    ),
                },
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }

    def normalize_request(self, body: dict[str, Any]) -> dict[str, Any]:
        import copy
        normalized = copy.deepcopy(body)
        # Phase 1: force non-streaming to avoid SSE buffering complexity
        normalized["stream"] = False
        return normalized

    # -- StreamingCapableHandler -------------------------------------------
    #
    # See this module's top-level docstring for the two structural
    # differences from Anthropic's format these methods work around:
    # no per-block close event (every tool call resolves together, at the
    # finish_reason chunk), and id/function.name not guaranteed to arrive
    # in the same chunk as the first argument fragment for that index.

    def normalize_stream_request(self, body: dict[str, Any]) -> dict[str, Any]:
        import copy
        normalized = copy.deepcopy(body)
        normalized["stream"] = True
        return normalized

    def classify_stream_event(self, event: SSEEvent) -> StreamEventInfo:
        if event.is_comment:
            return StreamEventInfo(kind=StreamBlockKind.PING)

        # OpenAI's stream terminator — a literal "[DONE]" payload, not JSON,
        # and (unlike Anthropic) OpenAI never sets the SSE `event:` field at
        # all, so classification here is purely data-shape-driven throughout
        # this method.
        if event.data.strip() == "[DONE]":
            return StreamEventInfo(kind=StreamBlockKind.STREAM_END)

        try:
            payload = json.loads(event.data) if event.data else {}
        except json.JSONDecodeError:
            return StreamEventInfo(kind=StreamBlockKind.PASSTHROUGH)

        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            # e.g. the trailing usage-only chunk some gateways send when
            # stream_options.include_usage is set (choices: [], top-level
            # usage) — nothing to classify, forward untouched. Also covers
            # any response shaped with zero choices for other reasons.
            return StreamEventInfo(kind=StreamBlockKind.PASSTHROUGH)

        # Only choices[0] is handled — this streaming implementation
        # assumes n=1 (a single completion stream), matching the vast
        # majority of real tool-calling clients. extract_tool_calls()
        # (the non-streaming path) does handle multiple choices; per-choice
        # buffering state for n>1 streaming is unimplemented follow-up work.
        choice = choices[0]
        if not isinstance(choice, dict):
            return StreamEventInfo(kind=StreamBlockKind.PASSTHROUGH)

        if choice.get("finish_reason") is not None:
            return StreamEventInfo(kind=StreamBlockKind.MESSAGE_DELTA)

        delta = choice.get("delta")
        if not isinstance(delta, dict):
            return StreamEventInfo(kind=StreamBlockKind.PASSTHROUGH)

        tool_calls = delta.get("tool_calls")
        if isinstance(tool_calls, list) and tool_calls:
            if len(tool_calls) > 1:
                # Not observed in practice — real-world providers stream
                # parallel tool calls as separate, discrete chunks
                # distinguished by index, never bundled into one delta's
                # tool_calls array — but classify_stream_event can only
                # return one StreamEventInfo per raw event, so if this ever
                # occurs, only the first entry is processed. Logged loudly
                # rather than silently, since silently dropping a second
                # tool call would mean it's never scanned.
                logger.error(
                    "proxy_stream_multiple_tool_calls_in_one_chunk",
                    count=len(tool_calls),
                )
            tc = tool_calls[0]
            if not isinstance(tc, dict):
                return StreamEventInfo(kind=StreamBlockKind.PASSTHROUGH)
            index = tc.get("index")
            if not isinstance(index, int):
                # Every real provider includes index — it's the only
                # correlation key across chunks. Without it, forward
                # defensively rather than guess (matches
                # TOOL_BLOCK_START-missing-index's precedent below in
                # AnthropicFormatHandler / StreamingProxyPipeline).
                logger.warning("proxy_stream_tool_call_missing_index")
                return StreamEventInfo(kind=StreamBlockKind.PASSTHROUGH)
            fn_raw = tc.get("function")
            fn: dict[str, Any] = fn_raw if isinstance(fn_raw, dict) else {}
            return StreamEventInfo(
                kind=StreamBlockKind.TOOL_BLOCK_DELTA,
                block_index=index,
                tool_call_id=tc.get("id") or None,
                tool_name=fn.get("name") or None,
                json_fragment=fn.get("arguments") or "",
            )

        # Plain text, a role-only first chunk, a refusal/reasoning_content
        # field, or an empty delta with no finish_reason yet (a
        # heartbeat-shaped chunk some gateways send) — nothing to intercept.
        return StreamEventInfo(kind=StreamBlockKind.PASSTHROUGH)

    def assemble_tool_call(
        self, block_index: int, tool_call_id: str, tool_name: str, accumulated_json: str,
    ) -> ProxyToolCall:
        try:
            args = json.loads(accumulated_json or "{}")
        except json.JSONDecodeError:
            args = {"_raw": accumulated_json}
        return ProxyToolCall(
            id=tool_call_id,
            name=tool_name,
            arguments=args,
            raw={
                "id": tool_call_id, "type": "function",
                "function": {"name": tool_name, "arguments": accumulated_json},
            },
        )

    def build_blocked_stream_events(
        self, block_index: int, tool_call: ProxyToolCall, reason: str,
    ) -> list[SSEEvent]:
        explanation = (
            f"[AgentGuard] Tool call '{tool_call.name}' was blocked by the security policy. "
            f"Reason: {reason or 'policy violation'}."
        )
        return [
            SSEEvent(data=json.dumps({
                "id": "agentguard-blocked",
                "object": "chat.completion.chunk",
                "created": 0,
                "model": "agentguard",
                "choices": [{
                    "index": 0,
                    "delta": {"content": explanation},
                    "finish_reason": None,
                }],
            })),
        ]

    def patch_message_delta_after_block(self, event: SSEEvent) -> SSEEvent:
        try:
            payload = json.loads(event.data) if event.data else {}
        except json.JSONDecodeError:
            return event
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            return event
        choice = choices[0]
        if isinstance(choice, dict) and choice.get("finish_reason") == "tool_calls":
            # The tool_calls this finish_reason pointed at may have been
            # replaced by a text explanation — claiming "tool_calls" with
            # nothing left to call leaves the client unable to resume the
            # agent loop. "stop" matches build_blocked_response's
            # non-streaming equivalent for this same handler.
            patched_choice = {**choice, "finish_reason": "stop"}
            payload = {**payload, "choices": [patched_choice, *choices[1:]]}
            return SSEEvent(event=event.event, data=json.dumps(payload), id=event.id)
        return event

    def wrap_as_sse_stream(self, response_body: dict[str, Any]) -> list[SSEEvent]:
        model = response_body.get("model", "unknown")
        resp_id = response_body.get("id", "agentguard")
        events: list[SSEEvent] = []
        for choice in response_body.get("choices", []):
            if not isinstance(choice, dict):
                continue
            message = choice.get("message")
            content = message.get("content", "") if isinstance(message, dict) else ""
            events.append(SSEEvent(data=json.dumps({
                "id": resp_id, "object": "chat.completion.chunk", "created": 0, "model": model,
                "choices": [{
                    "index": 0, "delta": {"role": "assistant", "content": ""}, "finish_reason": None,
                }],
            })))
            if content:
                events.append(SSEEvent(data=json.dumps({
                    "id": resp_id, "object": "chat.completion.chunk", "created": 0, "model": model,
                    "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": None}],
                })))
            events.append(SSEEvent(data=json.dumps({
                "id": resp_id, "object": "chat.completion.chunk", "created": 0, "model": model,
                "choices": [{"index": 0, "delta": {}, "finish_reason": choice.get("finish_reason", "stop")}],
            })))
        events.append(SSEEvent(data="[DONE]"))
        return events


# ---------------------------------------------------------------------------
# Anthropic Messages  (/v1/messages)
# ---------------------------------------------------------------------------

class AnthropicFormatHandler(LLMFormatHandler, StreamingCapableHandler):
    """Handles Anthropic Messages API format."""

    def extract_inbound_texts(self, body: dict[str, Any]) -> list[ProxyInboundScanTarget]:
        targets: list[ProxyInboundScanTarget] = []

        # System prompt (top-level string or list of content blocks)
        system = body.get("system")
        if isinstance(system, str) and system.strip():
            targets.append(ProxyInboundScanTarget(text=system, role="system", message_index=-1))
        elif isinstance(system, list):
            for block in system:
                if isinstance(block, dict) and block.get("type") == "text":
                    text = block.get("text", "")
                    if text.strip():
                        targets.append(ProxyInboundScanTarget(text=text, role="system", message_index=-1))

        for i, msg in enumerate(body.get("messages", [])):
            role = msg.get("role", "unknown")
            content = msg.get("content", "")
            if isinstance(content, str) and content.strip():
                targets.append(ProxyInboundScanTarget(text=content, role=role, message_index=i))
            elif isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "text":
                        text = block.get("text", "")
                        if text.strip():
                            targets.append(ProxyInboundScanTarget(text=text, role=role, message_index=i))
                    elif block.get("type") == "tool_result":
                        # Tool result content can be a string or list of blocks
                        tool_content = block.get("content", "")
                        if isinstance(tool_content, str) and tool_content.strip():
                            targets.append(ProxyInboundScanTarget(
                                text=tool_content, role="tool_result", message_index=i
                            ))
                        elif isinstance(tool_content, list):
                            for inner in tool_content:
                                if isinstance(inner, dict) and inner.get("type") == "text":
                                    text = inner.get("text", "")
                                    if text.strip():
                                        targets.append(ProxyInboundScanTarget(
                                            text=text, role="tool_result", message_index=i
                                        ))
        return targets

    def extract_tool_calls(self, response_body: dict[str, Any]) -> list[ProxyToolCall]:
        tool_calls: list[ProxyToolCall] = []
        for block in response_body.get("content", []):
            if isinstance(block, dict) and block.get("type") == "tool_use":
                tool_calls.append(ProxyToolCall(
                    id=block.get("id", ""),
                    name=block.get("name", "unknown"),
                    arguments=block.get("input", {}),
                    raw=block,
                ))
        return tool_calls

    def extract_tool_names(self, body: dict[str, Any]) -> list[str]:
        tools = body.get("tools")
        if not isinstance(tools, list):
            return []
        return [
            t["name"] for t in tools
            if isinstance(t, dict) and isinstance(t.get("name"), str) and t["name"]
        ]

    def build_blocked_response(
        self,
        original_response: dict[str, Any],
        blocked_results: list[ProxyInterceptionResult],
        allowed_results: list[ProxyInterceptionResult],
    ) -> dict[str, Any]:
        import copy
        response = copy.deepcopy(original_response)

        blocked_ids = {r.tool_call.id for r in blocked_results}
        blocked_names = [r.tool_call.name for r in blocked_results]
        reasons = "; ".join(r.reason for r in blocked_results if r.reason)

        # Filter content blocks
        filtered_content = [
            block for block in response.get("content", [])
            if not (isinstance(block, dict) and block.get("type") == "tool_use" and block.get("id") in blocked_ids)
        ]

        # Inject text explanation
        explanation = (
            f"[AgentGuard] The following tool call(s) were blocked by the security policy: "
            f"{blocked_names}. Reason: {reasons or 'policy violation'}. "
            "Please adjust your approach and try again without these tools."
        )
        filtered_content.append({"type": "text", "text": explanation})

        response["content"] = filtered_content
        response["stop_reason"] = "end_turn"
        return response

    def build_inbound_block_response(self, reason: str, model: str) -> dict[str, Any]:
        return {
            "id": "agentguard-blocked",
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [{
                "type": "text",
                "text": (
                    f"[AgentGuard] This request was blocked by the security policy. "
                    f"Reason: {reason}"
                ),
            }],
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 0, "output_tokens": 0},
        }

    def normalize_request(self, body: dict[str, Any]) -> dict[str, Any]:
        import copy
        normalized = copy.deepcopy(body)
        # Phase 1: force non-streaming
        normalized["stream"] = False
        return normalized

    # -- StreamingCapableHandler -------------------------------------------

    def normalize_stream_request(self, body: dict[str, Any]) -> dict[str, Any]:
        import copy
        normalized = copy.deepcopy(body)
        normalized["stream"] = True
        return normalized

    def classify_stream_event(self, event: SSEEvent) -> StreamEventInfo:
        if event.is_comment or event.event == "ping":
            return StreamEventInfo(kind=StreamBlockKind.PING)
        try:
            payload = json.loads(event.data) if event.data else {}
        except json.JSONDecodeError:
            return StreamEventInfo(kind=StreamBlockKind.PASSTHROUGH)

        event_type = payload.get("type", event.event)

        if event_type == "content_block_start":
            block = payload.get("content_block", {})
            if isinstance(block, dict) and block.get("type") == "tool_use":
                return StreamEventInfo(
                    kind=StreamBlockKind.TOOL_BLOCK_START,
                    block_index=payload.get("index"),
                    tool_name=block.get("name", "unknown"),
                    tool_call_id=block.get("id", ""),
                )
            return StreamEventInfo(kind=StreamBlockKind.PASSTHROUGH)

        if event_type == "content_block_delta":
            delta = payload.get("delta", {})
            if isinstance(delta, dict) and delta.get("type") == "input_json_delta":
                return StreamEventInfo(
                    kind=StreamBlockKind.TOOL_BLOCK_DELTA,
                    block_index=payload.get("index"),
                    json_fragment=delta.get("partial_json", ""),
                )
            return StreamEventInfo(kind=StreamBlockKind.PASSTHROUGH)

        if event_type == "content_block_stop":
            return StreamEventInfo(kind=StreamBlockKind.BLOCK_STOP, block_index=payload.get("index"))

        if event_type == "message_delta":
            return StreamEventInfo(kind=StreamBlockKind.MESSAGE_DELTA)

        if event_type == "message_stop":
            return StreamEventInfo(kind=StreamBlockKind.STREAM_END)

        # message_start, error, and any future/unrecognized event types all
        # pass through untouched.
        return StreamEventInfo(kind=StreamBlockKind.PASSTHROUGH)

    def assemble_tool_call(
        self, block_index: int, tool_call_id: str, tool_name: str, accumulated_json: str,
    ) -> ProxyToolCall:
        try:
            args = json.loads(accumulated_json or "{}")
        except json.JSONDecodeError:
            args = {"_raw": accumulated_json}
        return ProxyToolCall(
            id=tool_call_id,
            name=tool_name,
            arguments=args,
            raw={"type": "tool_use", "id": tool_call_id, "name": tool_name, "input": args},
        )

    def build_blocked_stream_events(
        self, block_index: int, tool_call: ProxyToolCall, reason: str,
    ) -> list[SSEEvent]:
        explanation = (
            f"[AgentGuard] Tool call '{tool_call.name}' was blocked by the security policy. "
            f"Reason: {reason or 'policy violation'}."
        )
        return [
            SSEEvent(event="content_block_start", data=json.dumps({
                "type": "content_block_start", "index": block_index,
                "content_block": {"type": "text", "text": ""},
            })),
            SSEEvent(event="content_block_delta", data=json.dumps({
                "type": "content_block_delta", "index": block_index,
                "delta": {"type": "text_delta", "text": explanation},
            })),
            SSEEvent(event="content_block_stop", data=json.dumps({
                "type": "content_block_stop", "index": block_index,
            })),
        ]

    def patch_message_delta_after_block(self, event: SSEEvent) -> SSEEvent:
        try:
            payload = json.loads(event.data) if event.data else {}
        except json.JSONDecodeError:
            return event
        delta = payload.get("delta")
        if isinstance(delta, dict) and delta.get("stop_reason") == "tool_use":
            # The tool_use block(s) this stop_reason pointed at may have been
            # replaced by a text explanation — claiming "tool_use" with no
            # matching block leaves the client unable to resume the agent
            # loop. end_turn matches build_blocked_response's non-streaming
            # equivalent (format_handler.py's Anthropic build_blocked_response).
            payload = {**payload, "delta": {**delta, "stop_reason": "end_turn"}}
            return SSEEvent(event=event.event, data=json.dumps(payload), id=event.id)
        return event

    def wrap_as_sse_stream(self, response_body: dict[str, Any]) -> list[SSEEvent]:
        events: list[SSEEvent] = [
            SSEEvent(event="message_start", data=json.dumps({
                "type": "message_start",
                "message": {
                    "id": response_body.get("id", "agentguard"),
                    "type": "message",
                    "role": response_body.get("role", "assistant"),
                    "model": response_body.get("model", "unknown"),
                    "content": [],
                    "stop_reason": None,
                    "stop_sequence": None,
                    "usage": response_body.get("usage", {"input_tokens": 0, "output_tokens": 0}),
                },
            })),
        ]
        for i, block in enumerate(response_body.get("content", [])):
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text":
                events.append(SSEEvent(event="content_block_start", data=json.dumps({
                    "type": "content_block_start", "index": i,
                    "content_block": {"type": "text", "text": ""},
                })))
                events.append(SSEEvent(event="content_block_delta", data=json.dumps({
                    "type": "content_block_delta", "index": i,
                    "delta": {"type": "text_delta", "text": block.get("text", "")},
                })))
                events.append(SSEEvent(event="content_block_stop", data=json.dumps({
                    "type": "content_block_stop", "index": i,
                })))
            elif block.get("type") == "tool_use":
                events.append(SSEEvent(event="content_block_start", data=json.dumps({
                    "type": "content_block_start", "index": i,
                    "content_block": {
                        "type": "tool_use", "id": block.get("id", ""),
                        "name": block.get("name", "unknown"), "input": {},
                    },
                })))
                events.append(SSEEvent(event="content_block_delta", data=json.dumps({
                    "type": "content_block_delta", "index": i,
                    "delta": {"type": "input_json_delta", "partial_json": json.dumps(block.get("input", {}))},
                })))
                events.append(SSEEvent(event="content_block_stop", data=json.dumps({
                    "type": "content_block_stop", "index": i,
                })))
        events.append(SSEEvent(event="message_delta", data=json.dumps({
            "type": "message_delta",
            "delta": {
                "stop_reason": response_body.get("stop_reason", "end_turn"),
                "stop_sequence": response_body.get("stop_sequence"),
            },
            "usage": response_body.get("usage", {"output_tokens": 0}),
        })))
        events.append(SSEEvent(event="message_stop", data=json.dumps({"type": "message_stop"})))
        return events
