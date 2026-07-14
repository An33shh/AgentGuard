"""Internal Pydantic models for the LLM API Proxy pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ProxyInboundScanTarget:
    """A piece of text extracted from an inbound request to scan for threats."""

    text: str
    role: str           # "user", "system", "tool", etc.
    message_index: int  # Position in the messages array


@dataclass
class ProxyToolCall:
    """A tool call extracted from an LLM response."""

    id: str
    name: str
    arguments: dict[str, Any]
    # Original raw object (OpenAI dict or Anthropic dict) — needed for reassembly
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProxyInterceptionResult:
    """The result of running a single tool call through AgentGuard's Interceptor."""

    tool_call: ProxyToolCall
    allowed: bool
    reason: str = ""
    risk_score: float = 0.0


@dataclass
class ProxyRequestContext:
    """
    Metadata extracted from an inbound proxy request.

    Derived from custom headers, the system prompt, or the Authorization header
    (in that priority order).
    """

    agent_goal: str
    session_id: str
    agent_id: str
    framework: str = "proxy"
    correlation_id: str = ""          # X-Request-ID threaded through for audit correlation
    initiating_principal: str = ""    # auth header hash — identifies the controlling operator
    # Raw auth header value — used only for session/agent derivation, never logged
    _auth_header: str = field(default="", repr=False)
