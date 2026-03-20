"""
OpenClaw adapter for AgentGuard.

OpenClaw is a Node.js-based agent runtime. Two integration paths exist:

1. **ClawHub skill (TypeScript)** — recommended for most deployments.
   See ``examples/openclaw_skill.ts``.  The skill intercepts every outbound
   tool invocation and forwards it to the ``POST /api/v1/intercept`` endpoint
   before allowing execution.

2. **Python WebSocket client (this adapter)** — for Python code that
   communicates with an OpenClaw gateway directly.  Connect to OpenClaw's
   WebSocket control plane (default ``ws://127.0.0.1:18789``), subscribe to
   tool events, and call ``before_tool_call()`` before forwarding them.

Usage (Python WebSocket path)::

    from agentguard.core.secure_agent import SecureAgent
    from agentguard.adapters.openclaw import OpenClawAdapter

    guard  = SecureAgent.from_env(goal="Triage GitHub issues", framework="openclaw")
    adapter = guard.get_openclaw_adapter()

    # In your WebSocket message handler:
    async def on_tool_event(msg: dict) -> None:
        tool_name  = msg["skill"]          # OpenClaw skill identifier
        parameters = msg.get("args", {})
        try:
            await adapter.before_tool_call(tool_name, parameters)
            # Safe to forward — send APPROVE back to OpenClaw gateway
        except BlockedByAgentGuard as exc:
            # Send DENY back to OpenClaw gateway
            await deny_tool(msg["id"], reason=exc.event.assessment.reason)
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import structlog

from agentguard.adapters.base import AgentAdapter
from agentguard.core.exceptions import BlockedByAgentGuard
from agentguard.core.models import Decision, ProvenanceSourceType, ProvenanceTag

if TYPE_CHECKING:
    from agentguard.interceptor.interceptor import Interceptor

logger = structlog.get_logger(__name__)

# OpenClaw uses dot-namespaced skill names (e.g. "browser.navigate").
# Normalise them to the same format AgentGuard expects.
_SKILL_RE = re.compile(r"^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)*$")


def _normalise_skill_name(skill: str) -> str:
    """Convert OpenClaw skill identifiers to AgentGuard tool_name format."""
    return skill.strip().lower() if _SKILL_RE.match(skill.strip()) else skill


class OpenClawAdapter(AgentAdapter):
    """
    AgentGuard adapter for OpenClaw agent runtime.

    Intercepts tool calls from OpenClaw's WebSocket gateway before they
    execute, scoring intent and enforcing YAML policies.
    """

    def __init__(
        self,
        interceptor: "Interceptor",
        agent_goal: str,
        session_id: str,
        agent_id: str | None = None,
    ) -> None:
        self._interceptor = interceptor
        self._agent_goal = agent_goal
        self._session_id = session_id
        self._agent_id = agent_id

    async def before_tool_call(
        self,
        tool_name: str,
        parameters: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> None:
        """
        Intercept an OpenClaw skill invocation before it executes.

        Raises ``BlockedByAgentGuard`` if the action should be blocked.
        The caller must NOT forward the tool call to OpenClaw's gateway
        when this exception is raised.
        """
        normalised = _normalise_skill_name(tool_name)
        raw_payload = {"tool_name": normalised, "parameters": parameters}

        decision, event = await self._interceptor.intercept(
            raw_payload=raw_payload,
            agent_goal=self._agent_goal,
            session_id=self._session_id,
            agent_id=self._agent_id,
            provenance_tags=[
                ProvenanceTag(
                    source_type=ProvenanceSourceType.SYSTEM,
                    label="openclaw_adapter",
                )
            ],
            framework="openclaw",
        )

        if decision == Decision.BLOCK:
            logger.warning(
                "openclaw_tool_blocked",
                tool=normalised,
                risk_score=event.assessment.risk_score,
                reason=event.assessment.reason,
                session_id=self._session_id,
            )
            raise BlockedByAgentGuard(event)

        if decision == Decision.REVIEW:
            logger.info(
                "openclaw_tool_flagged_for_review",
                tool=normalised,
                risk_score=event.assessment.risk_score,
                session_id=self._session_id,
            )

    def get_framework_name(self) -> str:
        return "openclaw"
