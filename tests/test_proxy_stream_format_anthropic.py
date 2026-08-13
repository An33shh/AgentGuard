"""Tests for AnthropicFormatHandler's StreamingCapableHandler methods."""

from __future__ import annotations

import json

from agentguard.proxy.format_handler import AnthropicFormatHandler, StreamBlockKind
from agentguard.proxy.sse import SSEEvent

handler = AnthropicFormatHandler()


def sse(event: str, data: dict) -> SSEEvent:
    return SSEEvent(event=event, data=json.dumps(data))


class TestClassifyStreamEvent:
    def test_text_content_block_start_is_passthrough(self) -> None:
        info = handler.classify_stream_event(sse("content_block_start", {
            "type": "content_block_start", "index": 0,
            "content_block": {"type": "text", "text": ""},
        }))
        assert info.kind == StreamBlockKind.PASSTHROUGH

    def test_tool_use_content_block_start_is_tool_block_start(self) -> None:
        info = handler.classify_stream_event(sse("content_block_start", {
            "type": "content_block_start", "index": 2,
            "content_block": {"type": "tool_use", "id": "toolu_1", "name": "bash"},
        }))
        assert info.kind == StreamBlockKind.TOOL_BLOCK_START
        assert info.block_index == 2
        assert info.tool_call_id == "toolu_1"
        assert info.tool_name == "bash"

    def test_text_delta_is_passthrough(self) -> None:
        info = handler.classify_stream_event(sse("content_block_delta", {
            "type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": "hi"},
        }))
        assert info.kind == StreamBlockKind.PASSTHROUGH

    def test_input_json_delta_is_tool_block_delta(self) -> None:
        info = handler.classify_stream_event(sse("content_block_delta", {
            "type": "content_block_delta", "index": 2,
            "delta": {"type": "input_json_delta", "partial_json": '{"cmd":'},
        }))
        assert info.kind == StreamBlockKind.TOOL_BLOCK_DELTA
        assert info.block_index == 2
        assert info.json_fragment == '{"cmd":'

    def test_content_block_stop_is_block_stop(self) -> None:
        info = handler.classify_stream_event(sse("content_block_stop", {
            "type": "content_block_stop", "index": 2,
        }))
        assert info.kind == StreamBlockKind.BLOCK_STOP
        assert info.block_index == 2

    def test_message_stop_is_stream_end(self) -> None:
        info = handler.classify_stream_event(sse("message_stop", {"type": "message_stop"}))
        assert info.kind == StreamBlockKind.STREAM_END

    def test_message_start_is_passthrough(self) -> None:
        assert handler.classify_stream_event(
            sse("message_start", {"type": "message_start", "message": {}})
        ).kind == StreamBlockKind.PASSTHROUGH

    def test_message_delta_is_its_own_kind(self) -> None:
        # Must be distinguishable from PASSTHROUGH — it needs to carry
        # stop_reason correction when an earlier block in the same response
        # was replaced by a blocked-tool-call substitution.
        assert handler.classify_stream_event(
            sse("message_delta", {"type": "message_delta", "delta": {}})
        ).kind == StreamBlockKind.MESSAGE_DELTA

    def test_named_ping_event_is_ping(self) -> None:
        info = handler.classify_stream_event(SSEEvent(event="ping", data='{"type":"ping"}'))
        assert info.kind == StreamBlockKind.PING

    def test_comment_line_is_ping(self) -> None:
        info = handler.classify_stream_event(SSEEvent(is_comment=True))
        assert info.kind == StreamBlockKind.PING

    def test_malformed_json_never_raises_classifies_as_passthrough(self) -> None:
        info = handler.classify_stream_event(SSEEvent(event="content_block_delta", data="not json{"))
        assert info.kind == StreamBlockKind.PASSTHROUGH

    def test_unrecognized_event_type_is_passthrough(self) -> None:
        info = handler.classify_stream_event(sse("some_future_event", {"type": "some_future_event"}))
        assert info.kind == StreamBlockKind.PASSTHROUGH


class TestAssembleToolCall:
    def test_valid_json_fragments_parsed(self) -> None:
        tool_call = handler.assemble_tool_call(1, "toolu_1", "bash", '{"command": "ls"}')
        assert tool_call.id == "toolu_1"
        assert tool_call.name == "bash"
        assert tool_call.arguments == {"command": "ls"}

    def test_multiple_fragments_concatenated_before_parsing(self) -> None:
        # Simulates the caller having joined several partial_json deltas.
        fragments = '{"path": ' + '"README.md"}'
        tool_call = handler.assemble_tool_call(0, "t1", "read_file", fragments)
        assert tool_call.arguments == {"path": "README.md"}

    def test_malformed_json_falls_back_to_raw(self) -> None:
        tool_call = handler.assemble_tool_call(0, "t1", "bash", "{not valid json")
        assert tool_call.arguments == {"_raw": "{not valid json"}

    def test_empty_accumulated_json_defaults_to_empty_object(self) -> None:
        tool_call = handler.assemble_tool_call(0, "t1", "noop", "")
        assert tool_call.arguments == {}


class TestBuildBlockedStreamEvents:
    def test_produces_well_formed_text_block_triplet(self) -> None:
        tool_call = handler.assemble_tool_call(3, "toolu_9", "bash", "{}")
        events = handler.build_blocked_stream_events(3, tool_call, "matched deny_tools")

        assert [e.event for e in events] == [
            "content_block_start", "content_block_delta", "content_block_stop",
        ]
        start = json.loads(events[0].data)
        assert start["index"] == 3
        assert start["content_block"]["type"] == "text"

        delta = json.loads(events[1].data)
        assert delta["index"] == 3
        assert delta["delta"]["type"] == "text_delta"
        assert "bash" in delta["delta"]["text"]
        assert "matched deny_tools" in delta["delta"]["text"]
        assert "[AgentGuard]" in delta["delta"]["text"]

        stop = json.loads(events[2].data)
        assert stop["index"] == 3

    def test_block_index_preserved_for_later_blocks(self) -> None:
        tool_call = handler.assemble_tool_call(5, "t", "x", "{}")
        events = handler.build_blocked_stream_events(5, tool_call, "reason")
        for event in events:
            assert json.loads(event.data)["index"] == 5


class TestPatchMessageDeltaAfterBlock:
    def test_tool_use_stop_reason_rewritten_to_end_turn(self) -> None:
        # This is the actual bug: a response whose tool_use block got
        # replaced by a text explanation still claimed stop_reason=
        # "tool_use" with no matching block, which is what left the client
        # unable to extract a valid tool call and stuck retrying.
        event = sse("message_delta", {
            "type": "message_delta",
            "delta": {"stop_reason": "tool_use", "stop_sequence": None},
            "usage": {"output_tokens": 12},
        })
        patched = handler.patch_message_delta_after_block(event)
        payload = json.loads(patched.data)
        assert payload["delta"]["stop_reason"] == "end_turn"
        # Other fields must survive untouched
        assert payload["usage"]["output_tokens"] == 12

    def test_non_tool_use_stop_reason_left_untouched(self) -> None:
        event = sse("message_delta", {
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn", "stop_sequence": None},
        })
        patched = handler.patch_message_delta_after_block(event)
        assert json.loads(patched.data)["delta"]["stop_reason"] == "end_turn"

    def test_malformed_data_returned_unchanged(self) -> None:
        event = SSEEvent(event="message_delta", data="not json")
        assert handler.patch_message_delta_after_block(event) is event


class TestWrapAsSSEStream:
    def test_wraps_text_response_into_valid_sequence(self) -> None:
        body = {
            "id": "msg_1", "role": "assistant", "model": "claude",
            "content": [{"type": "text", "text": "hello"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 5, "output_tokens": 2},
        }
        events = handler.wrap_as_sse_stream(body)
        kinds = [e.event for e in events]
        assert kinds[0] == "message_start"
        assert kinds[-1] == "message_stop"
        assert "content_block_start" in kinds
        assert "content_block_delta" in kinds
        assert "content_block_stop" in kinds

        delta_events = [json.loads(e.data) for e in events if e.event == "content_block_delta"]
        assert any(d["delta"].get("text") == "hello" for d in delta_events)

    def test_wraps_inbound_block_response(self) -> None:
        blocked_body = handler.build_inbound_block_response("prompt injection detected", "claude")
        events = handler.wrap_as_sse_stream(blocked_body)
        text_deltas = [
            json.loads(e.data)["delta"]["text"]
            for e in events if e.event == "content_block_delta"
        ]
        assert any("prompt injection detected" in t for t in text_deltas)
        assert events[0].event == "message_start"
        assert events[-1].event == "message_stop"

    def test_wraps_tool_use_response(self) -> None:
        body = {
            "id": "msg_1", "role": "assistant", "model": "claude",
            "content": [{"type": "tool_use", "id": "t1", "name": "bash", "input": {"cmd": "ls"}}],
            "stop_reason": "tool_use",
            "usage": {},
        }
        events = handler.wrap_as_sse_stream(body)
        starts = [json.loads(e.data) for e in events if e.event == "content_block_start"]
        assert starts[0]["content_block"]["type"] == "tool_use"
        assert starts[0]["content_block"]["name"] == "bash"


class TestNormalizeStreamRequest:
    def test_forces_stream_true(self) -> None:
        body = {"model": "claude", "messages": [], "stream": False}
        normalized = handler.normalize_stream_request(body)
        assert normalized["stream"] is True
        # Original untouched (deep copy)
        assert body["stream"] is False

    def test_stream_true_stays_true(self) -> None:
        body = {"model": "claude", "messages": [], "stream": True}
        normalized = handler.normalize_stream_request(body)
        assert normalized["stream"] is True
