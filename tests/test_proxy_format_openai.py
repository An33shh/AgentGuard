"""Tests for OpenAI format handler."""

from __future__ import annotations

import pytest

from agentguard.proxy.format_handler import OpenAIFormatHandler
from agentguard.proxy.models import ProxyInterceptionResult, ProxyToolCall


@pytest.fixture
def handler() -> OpenAIFormatHandler:
    return OpenAIFormatHandler()


SIMPLE_REQUEST = {
    "model": "gpt-4o",
    "messages": [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "What files are in my home directory?"},
    ],
}

TOOL_CALL_RESPONSE = {
    "id": "chatcmpl-abc123",
    "object": "chat.completion",
    "model": "gpt-4o",
    "choices": [{
        "index": 0,
        "message": {
            "role": "assistant",
            "content": None,
            "tool_calls": [{
                "id": "call_001",
                "type": "function",
                "function": {
                    "name": "bash",
                    "arguments": '{"command": "ls -la ~"}',
                },
            }],
        },
        "finish_reason": "tool_calls",
    }],
}


class TestExtractInboundTexts:
    def test_extracts_user_message(self, handler: OpenAIFormatHandler) -> None:
        targets = handler.extract_inbound_texts(SIMPLE_REQUEST)
        texts = [t.text for t in targets]
        assert any("home directory" in t for t in texts)

    def test_extracts_system_prompt(self, handler: OpenAIFormatHandler) -> None:
        targets = handler.extract_inbound_texts(SIMPLE_REQUEST)
        roles = [t.role for t in targets]
        assert "system" in roles

    def test_skips_empty_messages(self, handler: OpenAIFormatHandler) -> None:
        body = {"messages": [{"role": "user", "content": "  "}]}
        assert handler.extract_inbound_texts(body) == []

    def test_handles_content_parts_array(self, handler: OpenAIFormatHandler) -> None:
        body = {"messages": [{
            "role": "user",
            "content": [{"type": "text", "text": "Describe this image"}],
        }]}
        targets = handler.extract_inbound_texts(body)
        assert len(targets) == 1
        assert targets[0].text == "Describe this image"

    def test_empty_messages(self, handler: OpenAIFormatHandler) -> None:
        assert handler.extract_inbound_texts({}) == []


class TestExtractToolCalls:
    def test_extracts_tool_call(self, handler: OpenAIFormatHandler) -> None:
        tool_calls = handler.extract_tool_calls(TOOL_CALL_RESPONSE)
        assert len(tool_calls) == 1
        assert tool_calls[0].name == "bash"
        assert tool_calls[0].arguments == {"command": "ls -la ~"}
        assert tool_calls[0].id == "call_001"

    def test_no_tool_calls(self, handler: OpenAIFormatHandler) -> None:
        body = {"choices": [{"message": {"role": "assistant", "content": "Hello"}}]}
        assert handler.extract_tool_calls(body) == []

    def test_invalid_json_arguments(self, handler: OpenAIFormatHandler) -> None:
        body = {"choices": [{"message": {"tool_calls": [{
            "id": "c1",
            "function": {"name": "foo", "arguments": "not-json"},
        }]}}]}
        tool_calls = handler.extract_tool_calls(body)
        assert len(tool_calls) == 1
        assert "_raw" in tool_calls[0].arguments

    def test_multiple_tool_calls(self, handler: OpenAIFormatHandler) -> None:
        body = {"choices": [{"message": {"tool_calls": [
            {"id": "c1", "function": {"name": "read", "arguments": '{"path": "a"}'}},
            {"id": "c2", "function": {"name": "write", "arguments": '{"path": "b"}'}},
        ]}}]}
        tool_calls = handler.extract_tool_calls(body)
        assert len(tool_calls) == 2
        assert {tc.name for tc in tool_calls} == {"read", "write"}


class TestBuildBlockedResponse:
    def test_removes_blocked_tool_call(self, handler: OpenAIFormatHandler) -> None:
        tc = ProxyToolCall(id="call_001", name="bash", arguments={"command": "ls"}, raw={})
        blocked = [ProxyInterceptionResult(tool_call=tc, allowed=False, reason="deny_tools")]
        result = handler.build_blocked_response(TOOL_CALL_RESPONSE, blocked)
        message = result["choices"][0]["message"]
        assert not message.get("tool_calls")
        assert "AgentGuard" in message["content"]
        assert "bash" in message["content"]

    def test_keeps_allowed_tool_calls(self, handler: OpenAIFormatHandler) -> None:
        body = {"choices": [{"message": {"tool_calls": [
            {"id": "c1", "function": {"name": "bash", "arguments": "{}"}},
            {"id": "c2", "function": {"name": "read", "arguments": "{}"}},
        ], "content": None}, "finish_reason": "tool_calls"}]}
        tc_blocked = ProxyToolCall(id="c1", name="bash", arguments={}, raw={})
        blocked = [ProxyInterceptionResult(tool_call=tc_blocked, allowed=False, reason="deny")]
        result = handler.build_blocked_response(body, blocked)
        remaining = result["choices"][0]["message"].get("tool_calls", [])
        assert len(remaining) == 1
        assert remaining[0]["id"] == "c2"
        assert result["choices"][0]["finish_reason"] == "tool_calls"

    def test_does_not_mutate_original(self, handler: OpenAIFormatHandler) -> None:
        import copy
        original = copy.deepcopy(TOOL_CALL_RESPONSE)
        tc = ProxyToolCall(id="call_001", name="bash", arguments={}, raw={})
        blocked = [ProxyInterceptionResult(tool_call=tc, allowed=False)]
        handler.build_blocked_response(TOOL_CALL_RESPONSE, blocked)
        # Original unchanged
        assert TOOL_CALL_RESPONSE == original


class TestBuildInboundBlockResponse:
    def test_returns_valid_chat_completion(self, handler: OpenAIFormatHandler) -> None:
        resp = handler.build_inbound_block_response("injection detected", "gpt-4o")
        assert resp["object"] == "chat.completion"
        assert "AgentGuard" in resp["choices"][0]["message"]["content"]
        assert "injection detected" in resp["choices"][0]["message"]["content"]

    def test_finish_reason_stop(self, handler: OpenAIFormatHandler) -> None:
        resp = handler.build_inbound_block_response("test", "gpt-4o")
        assert resp["choices"][0]["finish_reason"] == "stop"


class TestNormalizeRequest:
    def test_forces_stream_false(self, handler: OpenAIFormatHandler) -> None:
        body = {"model": "gpt-4o", "messages": [], "stream": True}
        normalized = handler.normalize_request(body)
        assert normalized["stream"] is False

    def test_does_not_mutate_original(self, handler: OpenAIFormatHandler) -> None:
        body = {"stream": True}
        handler.normalize_request(body)
        assert body["stream"] is True
