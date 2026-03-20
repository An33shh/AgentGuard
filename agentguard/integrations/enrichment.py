"""Native Claude async enrichment — replaces Rowboat for async security triage.

Runs fire-and-forget after BLOCK/REVIEW decisions. Uses forced tool_use
for structured output, same pattern as IntentAnalyzer.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Agent display name generation
# ---------------------------------------------------------------------------

# Haiku is used for naming — 10× cheaper than Sonnet, fast, trivially capable for this.
_NAME_MODEL = "claude-haiku-4-5-20251001"
# System prompt kept minimal: every token saved is saved on every new agent seen.
_NAME_SYSTEM = "Reply with only a 2-4 word Title Case display name for an AI agent. No punctuation, no explanation."

_STRIP_VERBS = re.compile(
    r"^(summarize|triage|set up|research|analyze|monitor|review|fetch|"
    r"retrieve|create|generate|build|deploy|configure|manage|process|"
    r"execute|run|perform|help|assist|investigate|check|scan|"
    r"find|search|collect|extract|transform|load|send|post|update|"
    r"delete|remove|install|initialize|write|read|list|get|show)\s+",
    re.IGNORECASE,
)
_STRIP_ARTICLES = re.compile(r"^(the|a|an|this|that|these|those|my|our|all)\s+", re.IGNORECASE)
_STRIP_TRAILING = re.compile(
    r"\s+(and\s+(create|summarize|generate|return|write|send|produce|report)\b.*)$",
    re.IGNORECASE,
)


def _title_word(w: str) -> str:
    """Title-case a single word, preserving all-caps acronyms and filenames."""
    if not w:
        return w
    # Preserve acronyms (README, API, AWS, SSH) and filenames (README.md, .env)
    if w.isupper() or any(c in w for c in "./-_"):
        return w
    return w[0].upper() + w[1:]


def _rule_based_name(goal: str) -> str:
    """
    Generate a readable display name from a raw goal string without LLM.

    "Summarize the README.md file"              → "README.md File"
    "Triage open GitHub issues and create ..."  → "GitHub Issues"
    "Set up the development environment"        → "Development Environment"
    "Research competitor products and ..."      → "Competitor Products"
    """
    clean = _STRIP_VERBS.sub("", goal.strip())
    clean = _STRIP_ARTICLES.sub("", clean)
    clean = _STRIP_TRAILING.sub("", clean)
    words = clean.split()
    if len(words) > 4:
        words = words[:4]
    result = " ".join(_title_word(w) for w in words)
    return result or goal[:30]


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
        # Process-local cache: agent_id → display_name (avoids redundant LLM calls)
        self._name_cache: dict[str, str] = {}

        if not self._enabled:
            logger.warning("enrichment_disabled", reason="ANTHROPIC_API_KEY not set")

    @property
    def enabled(self) -> bool:
        return self._enabled

    def get_display_name(self, agent_id: str, goal: str, framework: str, is_registered: bool = False) -> str:
        """
        Return a display name for an agent immediately — zero latency, never blocks.

        Registered agents (explicit agent_id):
          Uses the agent_id formatted as a human-readable name (hyphens/underscores →
          spaces, Title Case). This is stable regardless of which goal string Claude
          happens to use in a given session.

        Auto-detected agents (derived slug-hash):
          1. Returns a rule-based name from the goal string instantly.
          2. If ANTHROPIC_API_KEY is set, schedules a background Haiku call to produce a
             richer name. The result overwrites the cache entry for the next request.

        All results are cached per agent_id — O(1) on every subsequent call.
        """
        if agent_id in self._name_cache:
            return self._name_cache[agent_id]

        if is_registered:
            # Format the explicit agent_id: "openclaw-demo-agent" → "Openclaw Demo Agent"
            name = " ".join(_title_word(w) for w in re.split(r"[-_]", agent_id))
            self._name_cache[agent_id] = name
            return name

        # Auto-detected: seed with rule-based, refine with Claude in background
        rule_name = _rule_based_name(goal)
        self._name_cache[agent_id] = rule_name

        if self._enabled:
            import asyncio
            try:
                asyncio.get_running_loop().create_task(
                    self._refine_name_background(agent_id, goal)
                )
            except RuntimeError:
                pass  # no running loop (e.g. test context) — rule-based is fine

        return rule_name

    async def _refine_name_background(self, agent_id: str, goal: str) -> None:
        """
        Background: call claude-haiku-4-5 to produce a better display name.

        Token budget per call:
          ~15 tokens system + ~12 tokens user + ~8 tokens output = ~35 tokens total.
        Called at most once per unique agent_id per process lifetime.
        """
        try:
            import anthropic
            client = anthropic.AsyncAnthropic(api_key=self._api_key)
            response = await client.messages.create(
                model=_NAME_MODEL,
                max_tokens=12,          # a 2-4 word name never needs more than 12 tokens
                system=_NAME_SYSTEM,
                messages=[{"role": "user", "content": f"Goal: {goal}"}],
                timeout=8.0,
            )
            name = response.content[0].text.strip().strip("\"'").strip()
            if name:
                self._name_cache[agent_id] = name
        except Exception as exc:
            # Rule-based name already in cache — this is a best-effort refinement.
            # Log at debug so systematic failures (e.g. API format changes) are visible.
            import structlog as _sl
            _sl.get_logger(__name__).debug(
                "name_refine_failed",
                agent_id=agent_id,
                error_type=type(exc).__name__,
                error=str(exc),
            )

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
