"""Core AgentGuard interception pipeline: normalize → analyze → enforce → log."""

from __future__ import annotations

import asyncio
import time
import uuid
from collections import defaultdict
from typing import Any

import structlog

from agentguard.core.models import Action, ActionType, Decision, Event, RiskAssessment
from agentguard.interceptor.action_types import (
    infer_action_type,
    is_credential_path,
    extract_file_path,
)
from agentguard.integrations.rowboat import get_rowboat_client
from agentguard.integrations.stream import get_stream_publisher

logger = structlog.get_logger(__name__)


class ActionNormalizer:
    """Normalize raw payloads from various frameworks into Action objects."""

    @staticmethod
    def from_openai_tool_call(tool_call: dict[str, Any]) -> Action:
        """Normalize an OpenAI tool call dict into an Action."""
        import json

        function = tool_call.get("function", tool_call)
        tool_name = function.get("name", "unknown")
        raw_args = function.get("arguments", "{}")
        if isinstance(raw_args, str):
            try:
                parameters = json.loads(raw_args)
            except Exception:
                parameters = {"raw": raw_args}
        else:
            parameters = raw_args or {}

        action_type = infer_action_type(tool_name, parameters)
        if action_type in (ActionType.FILE_READ, ActionType.FILE_WRITE):
            path = extract_file_path(parameters)
            if path and is_credential_path(path):
                action_type = ActionType.CREDENTIAL_ACCESS

        return Action(
            tool_name=tool_name,
            type=action_type,
            parameters=parameters,
            raw_payload=tool_call,
        )

    @staticmethod
    def from_langgraph_message(message: Any) -> Action:
        """Normalize a LangGraph tool call message into an Action."""
        if hasattr(message, "tool_calls") and message.tool_calls:
            tc = message.tool_calls[0]
            tool_name = tc.get("name", "unknown") if isinstance(tc, dict) else getattr(tc, "name", "unknown")
            parameters = tc.get("args", {}) if isinstance(tc, dict) else getattr(tc, "args", {})
        elif hasattr(message, "name"):
            tool_name = message.name
            parameters = getattr(message, "args", {}) or {}
        else:
            tool_name = "unknown"
            parameters = {}

        action_type = infer_action_type(tool_name, parameters)
        if action_type in (ActionType.FILE_READ, ActionType.FILE_WRITE):
            path = extract_file_path(parameters)
            if path and is_credential_path(path):
                action_type = ActionType.CREDENTIAL_ACCESS

        return Action(
            tool_name=tool_name,
            type=action_type,
            parameters=parameters,
            raw_payload={"message": str(message)},
        )

    @staticmethod
    def from_dict(payload: dict[str, Any]) -> Action:
        """Normalize a generic dict payload into an Action."""
        tool_name = payload.get("tool_name") or payload.get("name") or payload.get("tool", "unknown")
        parameters = payload.get("parameters") or payload.get("args") or payload.get("input") or {}
        if not isinstance(parameters, dict):
            parameters = {"value": parameters}

        action_type_raw = payload.get("action_type") or payload.get("type")
        if action_type_raw:
            try:
                action_type = ActionType(action_type_raw)
            except ValueError:
                action_type = infer_action_type(tool_name, parameters)
        else:
            action_type = infer_action_type(tool_name, parameters)

        if action_type in (ActionType.FILE_READ, ActionType.FILE_WRITE):
            path = extract_file_path(parameters)
            if path and is_credential_path(path):
                action_type = ActionType.CREDENTIAL_ACCESS

        return Action(
            tool_name=tool_name,
            type=action_type,
            parameters=parameters,
            raw_payload=payload,
        )


class Interceptor:
    """
    Main AgentGuard orchestrator.

    Pipeline: normalize → session_limits → policy → analyze → risk → log → return
    """

    def __init__(
        self,
        analyzer: Any,
        policy_engine: Any,
        event_ledger: Any,
    ) -> None:
        self._analyzer = analyzer
        self._policy = policy_engine
        self._ledger = event_ledger
        # Per-session counters for session_limits enforcement (in-memory)
        self._session_stats: dict[str, dict[str, int]] = defaultdict(
            lambda: {"actions": 0, "blocked": 0}
        )
        self._stats_lock = asyncio.Lock()

    async def intercept(
        self,
        raw_payload: dict[str, Any],
        agent_goal: str,
        session_id: str | None = None,
        provenance: dict[str, Any] | None = None,
        framework: str = "unknown",
    ) -> tuple[Decision, Event]:
        """
        Intercept an agent action and return (decision, event).

        The action is blocked if the session has exceeded its limits,
        if a deterministic policy rule fires, or if the LLM risk score
        exceeds the configured threshold.
        """
        session_id = session_id or str(uuid.uuid4())
        provenance = provenance or {}
        t_start = time.monotonic()

        log = logger.bind(session_id=session_id, framework=framework)

        # 1. Normalize — use framework-appropriate normalizer
        if framework == "openai" and "function" in raw_payload:
            action = ActionNormalizer.from_openai_tool_call(raw_payload)
        else:
            action = ActionNormalizer.from_dict(raw_payload)

        log = log.bind(action_id=action.action_id, tool=action.tool_name, action_type=action.type.value)
        log.info("intercepting_action")

        # 2. Session limits (zero-latency, before any other rule)
        async with self._stats_lock:
            stats = self._session_stats[session_id]
            current_actions = stats["actions"]
            current_blocked = stats["blocked"]

        session_decision, session_violation = self._policy.evaluate_session_limits(
            current_actions, current_blocked
        )

        if session_decision == Decision.BLOCK and session_violation is not None:
            latency_ms = (time.monotonic() - t_start) * 1000
            assessment = RiskAssessment(
                risk_score=1.0,
                reason=f"Session limit exceeded: {session_violation.detail}",
                indicators=["session_limit"],
                is_goal_aligned=False,
                analyzer_model="policy_engine",
                latency_ms=latency_ms,
            )
            event = Event(
                session_id=session_id,
                agent_goal=agent_goal,
                action=action,
                assessment=assessment,
                decision=Decision.BLOCK,
                policy_violation=session_violation,
                provenance=provenance,
                framework=framework,
            )
            await self._ledger.append(event)
            async with self._stats_lock:
                self._session_stats[session_id]["actions"] += 1
                self._session_stats[session_id]["blocked"] += 1
            log.warning("action_blocked_session_limit", detail=session_violation.detail)
            return Decision.BLOCK, event

        # 3. Deterministic policy enforcement (zero-latency — runs before LLM)
        decision, violation = self._policy.evaluate(action)

        if decision == Decision.BLOCK and violation is not None:
            # Fast-path: blocked by deterministic rule, skip LLM call
            latency_ms = (time.monotonic() - t_start) * 1000
            assessment = RiskAssessment(
                risk_score=0.95 if action.type == ActionType.CREDENTIAL_ACCESS else 0.80,
                reason=f"Policy rule '{violation.rule_name}' triggered: {violation.detail}",
                indicators=[violation.rule_type],
                is_goal_aligned=False,
                analyzer_model="policy_engine",
                latency_ms=latency_ms,
            )
            log.warning(
                "action_blocked_by_policy",
                rule=violation.rule_name,
                detail=violation.detail,
            )
        else:
            # 4. Intent analysis via Claude
            assessment = await self._analyzer.analyze(action, agent_goal)
            log = log.bind(risk_score=assessment.risk_score)

            # 5. Re-evaluate policy with risk score if not already blocked
            if decision != Decision.BLOCK:
                risk_decision, risk_violation = self._policy.evaluate_risk(assessment.risk_score)
                if risk_decision == Decision.BLOCK:
                    decision = Decision.BLOCK
                    violation = risk_violation
                elif risk_decision == Decision.REVIEW and decision == Decision.ALLOW:
                    decision = Decision.REVIEW
                    violation = risk_violation

        latency_ms = (time.monotonic() - t_start) * 1000

        event = Event(
            session_id=session_id,
            agent_goal=agent_goal,
            action=action,
            assessment=assessment,
            decision=decision,
            policy_violation=violation,
            provenance=provenance,
            framework=framework,
        )

        # 6. Log to ledger
        await self._ledger.append(event)

        # 7. Async Rowboat enrichment — fire-and-forget, zero latency impact
        if decision in (Decision.BLOCK, Decision.REVIEW):
            publisher = get_stream_publisher()
            if publisher.enabled:
                # Redis Streams path: durable, survives Rowboat restarts
                asyncio.create_task(self._publish_to_stream(event, publisher))
            elif get_rowboat_client().enabled:
                # Direct async fallback (no Redis): same process, task-based
                asyncio.create_task(self._enrich_with_rowboat(event))

        # 8. Update session counters
        async with self._stats_lock:
            self._session_stats[session_id]["actions"] += 1
            if decision == Decision.BLOCK:
                self._session_stats[session_id]["blocked"] += 1

        if decision == Decision.BLOCK:
            log.warning("action_blocked", reason=assessment.reason, latency_ms=f"{latency_ms:.1f}ms")
        elif decision == Decision.REVIEW:
            log.warning("action_flagged_for_review", reason=assessment.reason)
        else:
            log.info("action_allowed", latency_ms=f"{latency_ms:.1f}ms")

        return decision, event

    async def _publish_to_stream(self, event: Event, publisher: Any) -> None:
        """Publish event to Redis Stream for Rowboat sidecar to consume."""
        try:
            await publisher.publish_event({
                "event_id": event.event_id,
                "session_id": event.session_id,
                "tool_name": event.action.tool_name,
                "decision": event.decision.value,
                "risk_score": str(event.assessment.risk_score),
                "reason": event.assessment.reason,
                "agent_goal": event.agent_goal,
            })
            logger.debug("event_published_to_stream", event_id=event.event_id)
        except Exception as exc:
            logger.warning("stream_publish_failed", event_id=event.event_id, error=str(exc))
            # Fallback to direct Rowboat call if Redis publish fails
            await self._enrich_with_rowboat(event)

    async def _enrich_with_rowboat(self, event: Event) -> None:
        """Fire-and-forget: send event to Rowboat for async multi-agent triage."""
        from agentguard.integrations.insights import get_insights_store

        rowboat = get_rowboat_client()
        store = get_insights_store()
        payload = {
            "event_id": event.event_id,
            "session_id": event.session_id,
            "tool_name": event.action.tool_name,
            "decision": event.decision.value,
            "risk_score": event.assessment.risk_score,
            "reason": event.assessment.reason,
            "agent_goal": event.agent_goal,
        }
        try:
            insight = await rowboat.triage_event(payload)
            store.put(insight)
            logger.info(
                "rowboat_triage_complete",
                event_id=event.event_id,
                attack_pattern=insight.attack_patterns,
                confidence=insight.confidence,
            )
        except Exception as exc:
            logger.warning("rowboat_triage_failed", event_id=event.event_id, error=str(exc))
