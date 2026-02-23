"""Native Claude async enrichment — replaces Rowboat for async security triage.

Runs fire-and-forget after BLOCK/REVIEW decisions. Uses forced tool_use
for structured output, same pattern as IntentAnalyzer.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

TRIAGE_TOOL = {
    "name": "security_triage",
    "description": "Classify a blocked or flagged AI agent action into a structured security insight.",
    "input_schema": {
        "type": "object",
        "properties": {
            "attack_pattern": {
                "type": "string",
                "enum": [
                    "credential_exfiltration",
                    "data_exfiltration",
                    "prompt_injection",
                    "goal_hijacking",
                    "memory_poisoning",
                    "privilege_escalation",
                    "lateral_movement",
                    "reconnaissance",
                    "none",
                ],
                "description": "Primary attack pattern, or 'none' if no clear pattern.",
            },
            "confidence": {
                "type": "number",
                "description": "Confidence in the classification, 0.0–1.0.",
            },
            "severity": {
                "type": "string",
                "enum": ["low", "medium", "high", "critical"],
            },
            "summary": {
                "type": "string",
                "description": "One-sentence plain-English summary of what the agent was attempting.",
            },
            "recommended_action": {
                "type": "string",
                "description": "What the security team should do in response.",
            },
            "false_positive_likelihood": {
                "type": "number",
                "description": "Likelihood this is a false positive, 0.0–1.0.",
            },
        },
        "required": [
            "attack_pattern",
            "confidence",
            "severity",
            "summary",
            "recommended_action",
            "false_positive_likelihood",
        ],
    },
}

SYSTEM_PROMPT = """\
You are a senior AI security analyst reviewing blocked or flagged actions from autonomous AI agents.
Your job is to classify each event into a structured security insight.
Be precise and conservative — only flag as high/critical severity when the evidence is clear.
"""


@dataclass
class EnrichmentInsight:
    event_id: str
    analysis: str
    attack_patterns: list[str]
    confidence: float
    severity: str
    recommended_action: str
    false_positive_likelihood: float
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class EnrichmentClient:
    """
    Async Claude-based security enrichment client.

    Configured via environment variables:
        ANTHROPIC_API_KEY         — required
        AGENTGUARD_ANALYZER_MODEL — default: claude-sonnet-4-6
        AGENTGUARD_ANALYZER_TIMEOUT — default: 30.0
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        timeout: float | None = None,
    ) -> None:
        self._api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self._model = model or os.getenv("AGENTGUARD_ANALYZER_MODEL", "claude-sonnet-4-6")
        self._timeout = timeout or float(os.getenv("AGENTGUARD_ANALYZER_TIMEOUT", "30.0"))
        self._enabled = bool(self._api_key)

        if not self._enabled:
            logger.warning("enrichment_disabled", reason="ANTHROPIC_API_KEY not set")

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def triage_event(self, event: dict[str, Any]) -> EnrichmentInsight:
        """Run async security triage on a BLOCK/REVIEW event using Claude."""
        if not self._enabled:
            return _fallback_insight(event["event_id"])

        user_message = (
            f"Review this blocked/flagged AI agent action:\n\n"
            f"Tool: {event.get('tool_name', 'unknown')}\n"
            f"Decision: {event.get('decision', 'unknown')}\n"
            f"Risk Score: {event.get('risk_score', 0.0)}\n"
            f"Agent Goal: {event.get('agent_goal', 'unknown')}\n"
            f"Reason: {event.get('reason', 'unknown')}\n"
            f"Session: {event.get('session_id', 'unknown')}"
        )

        try:
            import anthropic
            client = anthropic.AsyncAnthropic(api_key=self._api_key)
            response = await client.messages.create(
                model=self._model,
                max_tokens=512,
                system=SYSTEM_PROMPT,
                tools=[TRIAGE_TOOL],
                tool_choice={"type": "tool", "name": "security_triage"},
                messages=[{"role": "user", "content": user_message}],
                timeout=self._timeout,
            )

            tool_input: dict[str, Any] = {}
            for block in response.content:
                if block.type == "tool_use" and block.name == "security_triage":
                    tool_input = block.input
                    break

            pattern = tool_input.get("attack_pattern", "none")
            return EnrichmentInsight(
                event_id=event["event_id"],
                analysis=tool_input.get("summary", "Analysis unavailable"),
                attack_patterns=[pattern] if pattern and pattern != "none" else [],
                confidence=float(tool_input.get("confidence", 0.0)),
                severity=tool_input.get("severity", "low"),
                recommended_action=tool_input.get("recommended_action", "Monitor"),
                false_positive_likelihood=float(tool_input.get("false_positive_likelihood", 0.0)),
            )

        except Exception as exc:
            logger.warning("enrichment_triage_error", event_id=event.get("event_id"), error=str(exc))
            return _fallback_insight(event["event_id"])


def _fallback_insight(event_id: str) -> EnrichmentInsight:
    return EnrichmentInsight(
        event_id=event_id,
        analysis="Enrichment unavailable",
        attack_patterns=[],
        confidence=0.0,
        severity="low",
        recommended_action="Review manually",
        false_positive_likelihood=0.0,
    )


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_client: EnrichmentClient | None = None


def get_enrichment_client() -> EnrichmentClient:
    global _client
    if _client is None:
        _client = EnrichmentClient()
    return _client
