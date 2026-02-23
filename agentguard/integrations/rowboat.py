"""Rowboat multi-agent integration for async security analysis."""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)


class RowboatWorkflow(str, Enum):
    SECURITY_TRIAGE = "security_triage"
    POLICY_GENERATION = "policy_generation"


@dataclass
class RowboatInsight:
    event_id: str
    workflow: RowboatWorkflow
    analysis: str
    policy_suggestion: dict[str, Any] | None = None
    attack_patterns: list[str] = field(default_factory=list)
    confidence: float = 0.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

def _triage_prompt(event: dict[str, Any]) -> str:
    return f"""You are a security analyst reviewing a blocked or flagged AI agent action.

Event details:
- Tool: {event["tool_name"]}
- Decision: {event["decision"]}
- Risk Score: {event["risk_score"]}
- Agent Goal: {event["agent_goal"]}
- Reason: {event["reason"]}
- Session: {event["session_id"]}

Analyse this event and respond with a JSON object:
{{
  "attack_pattern": "name of the attack pattern (e.g. credential_exfiltration, prompt_injection, data_exfiltration, goal_hijacking, memory_poisoning) or null",
  "confidence": 0.0-1.0,
  "severity": "low|medium|high|critical",
  "summary": "one sentence plain-English summary",
  "recommended_action": "what the security team should do",
  "false_positive_likelihood": 0.0-1.0
}}"""


def _policy_prompt(description: str, existing_policy: dict[str, Any] | None = None) -> str:
    existing = f"\nExisting policy to refine:\n{existing_policy}" if existing_policy else ""
    return f"""You are a security policy expert for an AI agent runtime security system.

Agent description: {description}{existing}

Generate a security policy YAML configuration. Respond with ONLY valid YAML in this exact schema:
name: <descriptive name>
risk_threshold: <0.0-1.0, default 0.75>
review_threshold: <0.0-1.0, must be less than risk_threshold, default 0.60>
deny_tools:
  - <tool patterns to always block>
deny_path_patterns:
  - <file path glob patterns to block>
deny_domains:
  - <domain patterns to block>
review_tools:
  - <tool patterns that need review>
allow_tools:
  - <if strict mode: only these tools are permitted>
session_limits:
  max_actions: <int>
  max_blocked: <int>"""


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class RowboatClient:
    """
    Async HTTP client for Rowboat's multi-agent API.

    Configured via environment variables:
        ROWBOAT_API_URL       — e.g. http://localhost:3002
        ROWBOAT_API_KEY       — Bearer token
        ROWBOAT_PROJECT_ID    — Project ID from Rowboat UI
        ROWBOAT_WORKFLOW_TRIAGE_ID   — Workflow ID for security triage
        ROWBOAT_WORKFLOW_POLICY_ID   — Workflow ID for policy generation
    """

    def __init__(
        self,
        api_url: str | None = None,
        api_key: str | None = None,
        project_id: str | None = None,
        triage_workflow_id: str | None = None,
        policy_workflow_id: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._api_url = (api_url or os.getenv("ROWBOAT_API_URL", "")).rstrip("/")
        self._api_key = api_key or os.getenv("ROWBOAT_API_KEY", "")
        self._project_id = project_id or os.getenv("ROWBOAT_PROJECT_ID", "")
        self._triage_workflow_id = triage_workflow_id or os.getenv("ROWBOAT_WORKFLOW_TRIAGE_ID", "")
        self._policy_workflow_id = policy_workflow_id or os.getenv("ROWBOAT_WORKFLOW_POLICY_ID", "")
        self._timeout = timeout
        self._enabled = bool(self._api_url and self._api_key and self._project_id)

        if not self._enabled:
            logger.info("rowboat_disabled", reason="ROWBOAT_API_URL/KEY/PROJECT_ID not set")

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def _chat(self, workflow_id: str, message: str) -> str:
        """Send a single message to a Rowboat workflow and return the text response."""
        url = f"{self._api_url}/api/v1/{self._project_id}/chat"
        headers = {"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"}
        body = {
            "messages": [{"role": "user", "content": message}],
            "workflowId": workflow_id,
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(url, json=body, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            # Extract text content from Rowboat's response structure
            if isinstance(data, dict):
                # Try common response shapes
                for key in ("content", "message", "response", "text"):
                    if isinstance(data.get(key), str):
                        return data[key]
                # Nested messages array
                messages = data.get("messages", [])
                if messages:
                    last = messages[-1]
                    return last.get("content", str(data))
            return str(data)

    async def triage_event(self, event: dict[str, Any]) -> RowboatInsight:
        """Run security triage workflow on a BLOCK/REVIEW event."""
        import json

        prompt = _triage_prompt(event)
        try:
            raw = await self._chat(self._triage_workflow_id, prompt)
            # Parse JSON from response
            start = raw.find("{")
            end = raw.rfind("}") + 1
            parsed = json.loads(raw[start:end]) if start >= 0 else {}
        except Exception as exc:
            logger.warning("rowboat_triage_error", error=str(exc), event_id=event.get("event_id"))
            parsed = {}

        return RowboatInsight(
            event_id=event["event_id"],
            workflow=RowboatWorkflow.SECURITY_TRIAGE,
            analysis=parsed.get("summary", "Analysis unavailable"),
            attack_patterns=[p for p in [parsed.get("attack_pattern")] if p],
            confidence=float(parsed.get("confidence", 0.0)),
            policy_suggestion=None,
        )

    async def generate_policy(
        self,
        agent_description: str,
        existing_policy: dict[str, Any] | None = None,
    ) -> str:
        """Run policy generation workflow and return a YAML string."""
        prompt = _policy_prompt(agent_description, existing_policy)
        try:
            return await self._chat(self._policy_workflow_id, prompt)
        except Exception as exc:
            logger.warning("rowboat_policy_error", error=str(exc))
            raise


# ---------------------------------------------------------------------------
# Module-level singleton (lazy-initialised)
# ---------------------------------------------------------------------------

_client: RowboatClient | None = None


def get_rowboat_client() -> RowboatClient:
    global _client
    if _client is None:
        _client = RowboatClient()
    return _client
