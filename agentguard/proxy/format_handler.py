"""
LLM format handlers for OpenAI and Anthropic API schemas.

Each handler translates between the provider's wire format and AgentGuard's
internal proxy models, and back.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

from agentguard.proxy.models import (
    ProxyInboundScanTarget,
    ProxyInterceptionResult,
    ProxyToolCall,
)


class LLMFormatHandler(ABC):
    """Abstract base class for provider-specific format translation."""

    @abstractmethod
    def extract_inbound_texts(self, body: dict[str, Any]) -> list[ProxyInboundScanTarget]:
        """Extract all text segments from the request body for inbound scanning."""

    @abstractmethod
    def extract_tool_calls(self, response_body: dict[str, Any]) -> list[ProxyToolCall]:
        """Extract tool calls from an LLM response body."""

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


# ---------------------------------------------------------------------------
# OpenAI Chat Completions  (/v1/chat/completions)
# ---------------------------------------------------------------------------

class OpenAIFormatHandler(LLMFormatHandler):
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


# ---------------------------------------------------------------------------
# Anthropic Messages  (/v1/messages)
# ---------------------------------------------------------------------------

class AnthropicFormatHandler(LLMFormatHandler):
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
