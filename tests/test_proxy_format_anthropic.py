"""Tests for Anthropic format handler."""

from __future__ import annotations

import pytest

from agentguard.proxy.format_handler import AnthropicFormatHandler
from agentguard.proxy.models import ProxyInterceptionResult, ProxyToolCall


@pytest.fixture
def handler() -> AnthropicFormatHandler:
    return AnthropicFormatHandler()


SIMPLE_REQUEST = {
    "model": "claude-sonnet-4-6",
    "system": "You are a helpful assistant.",
    "messages": [
        {"role": "user", "content": "What files are in my home directory?"},
    ],
    "max_tokens": 1024,
}

TOOL_USE_RESPONSE = {
    "id": "msg_abc123",
    "type": "message",
    "role": "assistant",
    "model": "claude-sonnet-4-6",
    "content": [{
        "type": "tool_use",
        "id": "toolu_01",
        "name": "bash",
        "input": {"command": "ls -la ~"},
    }],
    "stop_reason": "tool_use",
    "usage": {"input_tokens": 50, "output_tokens": 30},
}


class TestExtractInboundTexts:
    def test_extracts_user_message(self, handler: AnthropicFormatHandler) -> None:
        targets = handler.extract_inbound_texts(SIMPLE_REQUEST)
        texts = [t.text for t in targets]
        assert any("home directory" in t for t in texts)

    def test_extracts_system_string(self, handler: AnthropicFormatHandler) -> None:
        targets = handler.extract_inbound_texts(SIMPLE_REQUEST)
        roles = [t.role for t in targets]
        assert "system" in roles

    def test_extracts_system_content_block(self, handler: AnthropicFormatHandler) -> None:
        body = {
            "system": [{"type": "text", "text": "System instructions here."}],
            "messages": [],
        }
        targets = handler.extract_inbound_texts(body)
        assert any(t.role == "system" for t in targets)

    def test_extracts_tool_result_string(self, handler: AnthropicFormatHandler) -> None:
        body = {"messages": [{
            "role": "user",
            "content": [{"type": "tool_result", "tool_use_id": "x", "content": "Tool returned: data"}],
        }]}
        targets = handler.extract_inbound_texts(body)
        assert any(t.role == "tool_result" for t in targets)

    def test_extracts_tool_result_content_blocks(self, handler: AnthropicFormatHandler) -> None:
        body = {"messages": [{
            "role": "user",
            "content": [{
                "type": "tool_result",
                "tool_use_id": "x",
                "content": [{"type": "text", "text": "some result"}],
            }],
        }]}
        targets = handler.extract_inbound_texts(body)
        assert any("some result" in t.text for t in targets)

    def test_skips_empty(self, handler: AnthropicFormatHandler) -> None:
        body = {"messages": [{"role": "user", "content": "  "}]}
        assert handler.extract_inbound_texts(body) == []


class TestExtractToolCalls:
    def test_extracts_tool_use_block(self, handler: AnthropicFormatHandler) -> None:
        tool_calls = handler.extract_tool_calls(TOOL_USE_RESPONSE)
        assert len(tool_calls) == 1
        assert tool_calls[0].name == "bash"
        assert tool_calls[0].arguments == {"command": "ls -la ~"}
        assert tool_calls[0].id == "toolu_01"

    def test_no_tool_calls(self, handler: AnthropicFormatHandler) -> None:
        body = {"content": [{"type": "text", "text": "Hello world"}]}
        assert handler.extract_tool_calls(body) == []

    def test_multiple_tool_calls(self, handler: AnthropicFormatHandler) -> None:
        body = {"content": [
            {"type": "tool_use", "id": "t1", "name": "read", "input": {"path": "a"}},
            {"type": "tool_use", "id": "t2", "name": "write", "input": {"path": "b"}},
        ]}
        tool_calls = handler.extract_tool_calls(body)
        assert len(tool_calls) == 2


class TestBuildBlockedResponse:
    def test_removes_blocked_tool_use(self, handler: AnthropicFormatHandler) -> None:
        tc = ProxyToolCall(id="toolu_01", name="bash", arguments={}, raw={})
        blocked = [ProxyInterceptionResult(tool_call=tc, allowed=False, reason="deny_tools")]
        result = handler.build_blocked_response(TOOL_USE_RESPONSE, blocked, [])
        content_types = [b["type"] for b in result["content"]]
        assert "tool_use" not in content_types
        assert "text" in content_types
        text_blocks = [b["text"] for b in result["content"] if b["type"] == "text"]
        assert any("AgentGuard" in t for t in text_blocks)

    def test_keeps_allowed_tool_calls(self, handler: AnthropicFormatHandler) -> None:
        body = {"content": [
            {"type": "tool_use", "id": "t1", "name": "bash", "input": {}},
            {"type": "tool_use", "id": "t2", "name": "read", "input": {}},
        ], "stop_reason": "tool_use"}
        tc_blocked = ProxyToolCall(id="t1", name="bash", arguments={}, raw={})
        tc_allowed = ProxyToolCall(id="t2", name="read", arguments={}, raw={})
        blocked = [ProxyInterceptionResult(tool_call=tc_blocked, allowed=False)]
        allowed = [ProxyInterceptionResult(tool_call=tc_allowed, allowed=True)]
        result = handler.build_blocked_response(body, blocked, allowed)
        tool_use_blocks = [b for b in result["content"] if b.get("type") == "tool_use"]
        assert len(tool_use_blocks) == 1
        assert tool_use_blocks[0]["id"] == "t2"

    def test_does_not_mutate_original(self, handler: AnthropicFormatHandler) -> None:
        import copy
        original = copy.deepcopy(TOOL_USE_RESPONSE)
        tc = ProxyToolCall(id="toolu_01", name="bash", arguments={}, raw={})
        blocked = [ProxyInterceptionResult(tool_call=tc, allowed=False)]
        handler.build_blocked_response(TOOL_USE_RESPONSE, blocked, [])
        assert TOOL_USE_RESPONSE == original


class TestBuildInboundBlockResponse:
    def test_returns_valid_message(self, handler: AnthropicFormatHandler) -> None:
        resp = handler.build_inbound_block_response("injection detected", "claude-sonnet-4-6")
        assert resp["type"] == "message"
        assert resp["role"] == "assistant"
        text = resp["content"][0]["text"]
        assert "AgentGuard" in text
        assert "injection detected" in text

    def test_stop_reason_end_turn(self, handler: AnthropicFormatHandler) -> None:
        resp = handler.build_inbound_block_response("test", "claude-sonnet-4-6")
        assert resp["stop_reason"] == "end_turn"


class TestNormalizeRequest:
    def test_forces_stream_false(self, handler: AnthropicFormatHandler) -> None:
        body = {"model": "claude-sonnet-4-6", "messages": [], "stream": True}
        normalized = handler.normalize_request(body)
        assert normalized["stream"] is False

    def test_does_not_mutate_original(self, handler: AnthropicFormatHandler) -> None:
        body = {"stream": True}
        handler.normalize_request(body)
        assert body["stream"] is True
