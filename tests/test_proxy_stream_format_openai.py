"""Tests for OpenAIFormatHandler's StreamingCapableHandler methods.

OpenAI's Chat Completions streaming format has no `event:` field at all
(unlike Anthropic) — classification is purely data-shape-driven — and
signals stream end via a literal "[DONE]" payload, not JSON.
"""

from __future__ import annotations

import json

from agentguard.proxy.format_handler import OpenAIFormatHandler, StreamBlockKind
from agentguard.proxy.sse import SSEEvent

handler = OpenAIFormatHandler()


def sse(data: dict) -> SSEEvent:
    return SSEEvent(data=json.dumps(data))


class TestClassifyStreamEvent:
    def test_role_only_first_chunk_is_passthrough(self) -> None:
        info = handler.classify_stream_event(sse({
            "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}, "finish_reason": None}],
        }))
        assert info.kind == StreamBlockKind.PASSTHROUGH

    def test_text_content_delta_is_passthrough(self) -> None:
        info = handler.classify_stream_event(sse({
            "choices": [{"index": 0, "delta": {"content": "hi"}, "finish_reason": None}],
        }))
        assert info.kind == StreamBlockKind.PASSTHROUGH

    def test_tool_call_delta_with_id_and_name_is_tool_block_delta(self) -> None:
        info = handler.classify_stream_event(sse({
            "choices": [{"index": 0, "delta": {"tool_calls": [
                {"index": 0, "id": "call_1", "type": "function",
                 "function": {"name": "bash", "arguments": ""}},
            ]}, "finish_reason": None}],
        }))
        assert info.kind == StreamBlockKind.TOOL_BLOCK_DELTA
        assert info.block_index == 0
        assert info.tool_call_id == "call_1"
        assert info.tool_name == "bash"
        assert info.json_fragment == ""

    def test_tool_call_delta_without_name_yet_still_classified(self) -> None:
        """Confirmed real-world behavior: some OpenAI-compatible providers
        send id/type on the first chunk for an index but withhold
        function.name until a later chunk. Must not crash or misclassify —
        tool_name comes back None, filled in by a later delta."""
        info = handler.classify_stream_event(sse({
            "choices": [{"index": 0, "delta": {"tool_calls": [
                {"index": 0, "id": "call_1", "type": "function", "function": {"arguments": ""}},
            ]}, "finish_reason": None}],
        }))
        assert info.kind == StreamBlockKind.TOOL_BLOCK_DELTA
        assert info.block_index == 0
        assert info.tool_call_id == "call_1"
        assert info.tool_name is None

    def test_tool_call_argument_continuation_has_no_id_or_name(self) -> None:
        """Subsequent chunks for the same index typically omit id/type/name
        entirely, carrying only the incremental arguments string."""
        info = handler.classify_stream_event(sse({
            "choices": [{"index": 0, "delta": {"tool_calls": [
                {"index": 0, "function": {"arguments": '{"cmd":'}},
            ]}, "finish_reason": None}],
        }))
        assert info.kind == StreamBlockKind.TOOL_BLOCK_DELTA
        assert info.block_index == 0
        assert info.tool_call_id is None
        assert info.tool_name is None
        assert info.json_fragment == '{"cmd":'

    def test_second_tool_call_distinguished_by_index(self) -> None:
        info = handler.classify_stream_event(sse({
            "choices": [{"index": 0, "delta": {"tool_calls": [
                {"index": 1, "id": "call_2", "type": "function",
                 "function": {"name": "read_file", "arguments": ""}},
            ]}, "finish_reason": None}],
        }))
        assert info.block_index == 1
        assert info.tool_call_id == "call_2"

    def test_finish_reason_chunk_is_message_delta(self) -> None:
        info = handler.classify_stream_event(sse({
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
        }))
        assert info.kind == StreamBlockKind.MESSAGE_DELTA

    def test_finish_reason_tool_calls_is_message_delta(self) -> None:
        info = handler.classify_stream_event(sse({
            "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
        }))
        assert info.kind == StreamBlockKind.MESSAGE_DELTA

    def test_done_sentinel_is_stream_end(self) -> None:
        info = handler.classify_stream_event(SSEEvent(data="[DONE]"))
        assert info.kind == StreamBlockKind.STREAM_END

    def test_done_sentinel_with_surrounding_whitespace(self) -> None:
        info = handler.classify_stream_event(SSEEvent(data=" [DONE] "))
        assert info.kind == StreamBlockKind.STREAM_END

    def test_empty_choices_array_is_passthrough(self) -> None:
        """The trailing usage-only chunk some gateways send (stream_options
        .include_usage) has choices: [] — must not crash indexing choices[0]."""
        info = handler.classify_stream_event(sse({
            "choices": [], "usage": {"total_tokens": 42},
        }))
        assert info.kind == StreamBlockKind.PASSTHROUGH

    def test_missing_choices_key_is_passthrough(self) -> None:
        info = handler.classify_stream_event(sse({"id": "x"}))
        assert info.kind == StreamBlockKind.PASSTHROUGH

    def test_comment_line_is_ping(self) -> None:
        info = handler.classify_stream_event(SSEEvent(is_comment=True))
        assert info.kind == StreamBlockKind.PING

    def test_malformed_json_never_raises_classifies_as_passthrough(self) -> None:
        info = handler.classify_stream_event(SSEEvent(data="not json{"))
        assert info.kind == StreamBlockKind.PASSTHROUGH

    def test_tool_call_missing_index_forwarded_defensively(self) -> None:
        info = handler.classify_stream_event(sse({
            "choices": [{"index": 0, "delta": {"tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": "bash", "arguments": ""}},
            ]}, "finish_reason": None}],
        }))
        assert info.kind == StreamBlockKind.PASSTHROUGH

    def test_multiple_tool_calls_in_one_chunk_uses_first_only(self) -> None:
        """Not observed in real-world behavior (providers stream parallel
        tool calls as discrete chunks), but must degrade safely — not
        crash — rather than silently drop everything if it ever occurs."""
        info = handler.classify_stream_event(sse({
            "choices": [{"index": 0, "delta": {"tool_calls": [
                {"index": 0, "id": "call_1", "type": "function", "function": {"name": "a", "arguments": ""}},
                {"index": 1, "id": "call_2", "type": "function", "function": {"name": "b", "arguments": ""}},
            ]}, "finish_reason": None}],
        }))
        assert info.kind == StreamBlockKind.TOOL_BLOCK_DELTA
        assert info.block_index == 0
        assert info.tool_name == "a"


class TestAssembleToolCall:
    def test_valid_json_fragments_parsed(self) -> None:
        tool_call = handler.assemble_tool_call(0, "call_1", "bash", '{"command": "ls"}')
        assert tool_call.id == "call_1"
        assert tool_call.name == "bash"
        assert tool_call.arguments == {"command": "ls"}

    def test_malformed_json_falls_back_to_raw(self) -> None:
        tool_call = handler.assemble_tool_call(0, "call_1", "bash", "{not valid json")
        assert tool_call.arguments == {"_raw": "{not valid json"}

    def test_empty_accumulated_json_defaults_to_empty_object(self) -> None:
        tool_call = handler.assemble_tool_call(0, "call_1", "noop", "")
        assert tool_call.arguments == {}


class TestBuildBlockedStreamEvents:
    def test_produces_single_content_delta_chunk(self) -> None:
        tool_call = handler.assemble_tool_call(0, "call_1", "bash", "{}")
        events = handler.build_blocked_stream_events(0, tool_call, "matched deny_tools")
        assert len(events) == 1
        payload = json.loads(events[0].data)
        content = payload["choices"][0]["delta"]["content"]
        assert "bash" in content
        assert "matched deny_tools" in content
        assert "[AgentGuard]" in content
        assert events[0].event is None  # OpenAI never sets the SSE event: field


class TestPatchMessageDeltaAfterBlock:
    def test_tool_calls_finish_reason_rewritten_to_stop(self) -> None:
        event = sse({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]})
        patched = handler.patch_message_delta_after_block(event)
        assert json.loads(patched.data)["choices"][0]["finish_reason"] == "stop"

    def test_non_tool_calls_finish_reason_left_untouched(self) -> None:
        event = sse({"choices": [{"index": 0, "delta": {}, "finish_reason": "length"}]})
        patched = handler.patch_message_delta_after_block(event)
        assert json.loads(patched.data)["choices"][0]["finish_reason"] == "length"

    def test_malformed_data_returned_unchanged(self) -> None:
        event = SSEEvent(data="not json")
        assert handler.patch_message_delta_after_block(event) is event

    def test_empty_choices_returned_unchanged(self) -> None:
        event = sse({"choices": []})
        assert handler.patch_message_delta_after_block(event) is event


class TestWrapAsSSEStream:
    def test_wraps_text_response_into_valid_sequence_ending_in_done(self) -> None:
        body = {
            "id": "chatcmpl-1", "model": "gpt-4o",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "hello"}, "finish_reason": "stop"}],
        }
        events = handler.wrap_as_sse_stream(body)
        assert events[-1].data == "[DONE]"
        payloads = [json.loads(e.data) for e in events[:-1]]
        assert any(
            p["choices"][0]["delta"].get("content") == "hello" for p in payloads
        )
        assert payloads[-1]["choices"][0]["finish_reason"] == "stop"

    def test_wraps_inbound_block_response(self) -> None:
        blocked_body = handler.build_inbound_block_response("prompt injection detected", "gpt-4o")
        events = handler.wrap_as_sse_stream(blocked_body)
        payloads = [json.loads(e.data) for e in events[:-1]]
        assert any(
            "prompt injection detected" in p["choices"][0]["delta"].get("content", "")
            for p in payloads
        )
        assert events[-1].data == "[DONE]"


class TestNormalizeStreamRequest:
    def test_forces_stream_true(self) -> None:
        body = {"model": "gpt-4o", "messages": [], "stream": False}
        normalized = handler.normalize_stream_request(body)
        assert normalized["stream"] is True
        assert body["stream"] is False  # original untouched (deep copy)
