"""Core AgentGuard interception pipeline: normalize → analyze → enforce → log."""

from __future__ import annotations

import asyncio
import time
import uuid
from collections import defaultdict
from typing import Any

import structlog

from agentguard.core.models import Action, ActionType, Decision, Event, ProvenanceTag, RiskAssessment, derive_agent_id
from agentguard.interceptor.action_types import (
    infer_action_type,
    is_credential_path,
    extract_file_path,
)
from agentguard.integrations.enrichment import get_enrichment_client
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
            except json.JSONDecodeError as exc:
                import structlog as _sl
                _sl.get_logger(__name__).warning(
                    "tool_args_json_parse_failed", tool=tool_name, error=str(exc)
                )
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


_SESSION_HISTORY_MAX = 5


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
        # Per-session action history for multi-step attack detection
        self._session_history: dict[str, list[dict]] = defaultdict(list)
        self._stats_lock = asyncio.Lock()

    async def intercept(
        self,
        raw_payload: dict[str, Any],
        agent_goal: str,
        session_id: str | None = None,
        agent_id: str | None = None,
        provenance: dict[str, Any] | None = None,
        provenance_tags: list[ProvenanceTag] | None = None,
        framework: str = "unknown",
    ) -> tuple[Decision, Event]:
        """
        Intercept an agent action and return (decision, event).

        The action is blocked if the session has exceeded its limits,
        if a deterministic policy rule fires, or if the LLM risk score
        exceeds the configured threshold.
        """
        session_id = session_id or str(uuid.uuid4())
        resolved_provenance_tags = provenance_tags or []
        t_start = time.monotonic()

        # Two-tier agent identity: explicit (registered) or derived (auto-detected)
        is_registered = bool(agent_id)
        resolved_agent_id = agent_id or derive_agent_id(agent_goal, framework)

        log = logger.bind(session_id=session_id, framework=framework)

        try:
            return await self._intercept_inner(
                raw_payload=raw_payload,
                agent_goal=agent_goal,
                session_id=session_id,
                agent_id=agent_id,
                provenance_tags=resolved_provenance_tags,
                framework=framework,
                is_registered=is_registered,
                resolved_agent_id=resolved_agent_id,
                t_start=t_start,
                log=log,
            )
        except Exception as exc:
            # Fail-closed: an unhandled error in the pipeline must never silently
            # allow an action through. Block and log the error for investigation.
            latency_ms = (time.monotonic() - t_start) * 1000
            log.error(
                "intercept_pipeline_error",
                error=str(exc),
                error_type=type(exc).__name__,
                latency_ms=f"{latency_ms:.1f}ms",
                exc_info=True,
            )
            assessment = RiskAssessment(
                risk_score=1.0,
                reason=f"Pipeline error (fail-closed): {type(exc).__name__}",
                indicators=["pipeline_error"],
                is_goal_aligned=False,
                analyzer_model="interceptor",
                latency_ms=latency_ms,
            )
            action = ActionNormalizer.from_dict(raw_payload)
            event = Event(
                session_id=session_id,
                agent_id=resolved_agent_id,
                agent_is_registered=is_registered,
                agent_goal=agent_goal,
                action=action,
                assessment=assessment,
                decision=Decision.BLOCK,
                policy_violation=None,
                provenance=resolved_provenance_tags,
                framework=framework,
            )
            return Decision.BLOCK, event

    async def _intercept_inner(
        self,
        raw_payload: dict[str, Any],
        agent_goal: str,
        session_id: str,
        agent_id: str | None,
        provenance_tags: list[ProvenanceTag],
        framework: str,
        is_registered: bool,
        resolved_agent_id: str,
        t_start: float,
        log: Any,
    ) -> tuple[Decision, Event]:

        # 1. Normalize — use framework-appropriate normalizer
        if framework == "openai" and "function" in raw_payload:
            action = ActionNormalizer.from_openai_tool_call(raw_payload)
        else:
            action = ActionNormalizer.from_dict(raw_payload)

        log = log.bind(action_id=action.action_id, tool=action.tool_name, action_type=action.type.value)
        log.info("intercepting_action")

        # 2. Session limits (zero-latency, before any other rule)
        # Atomically read stats, check limits, and pre-increment the action counter
        # under one lock acquisition to eliminate the TOCTOU window that would
        # otherwise allow concurrent requests to bypass max_actions / max_blocked.
        session_decision = session_violation = None
        async with self._stats_lock:
            stats = self._session_stats[session_id]
            current_actions = stats["actions"]
            current_blocked = stats["blocked"]
            session_context = list(self._session_history[session_id])
            session_decision, session_violation = self._policy.evaluate_session_limits(
                current_actions, current_blocked
            )
            if session_decision != Decision.BLOCK:
                # Reserve the slot — no concurrent coroutine can also pass this
                # limit check for the same session until the lock is released.
                stats["actions"] += 1

        # Compute effective thresholds — tighter if session is demoted
        risk_threshold, review_threshold = self._policy.effective_thresholds(current_blocked)
        is_demoted = (
            self._policy.config.demotion.enabled
            and current_blocked >= self._policy.config.demotion.trigger_blocked_count
        )
        if is_demoted:
            log.warning(
                "session_demoted",
                blocked_count=current_blocked,
                effective_risk_threshold=risk_threshold,
                effective_review_threshold=review_threshold,
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
                agent_id=resolved_agent_id,
                agent_is_registered=is_registered,
                agent_goal=agent_goal,
                action=action,
                assessment=assessment,
                decision=Decision.BLOCK,
                policy_violation=session_violation,
                provenance=provenance_tags,
                framework=framework,
            )
            await self._ledger.append(event)
            async with self._stats_lock:
                # Session limit hit: still count both action + blocked.
                self._session_stats[session_id]["actions"] += 1
                self._session_stats[session_id]["blocked"] += 1
            log.warning("action_blocked_session_limit", detail=session_violation.detail)
            return Decision.BLOCK, event

        # 3. ABAC — attribute-based access control (e.g. deny_unregistered_tools)
        abac_decision, abac_violation = self._policy.evaluate_abac(action, is_registered)
        if abac_decision == Decision.BLOCK and abac_violation is not None:
            latency_ms = (time.monotonic() - t_start) * 1000
            assessment = RiskAssessment(
                risk_score=1.0,
                reason=abac_violation.detail,
                indicators=["abac_violation"],
                is_goal_aligned=False,
                analyzer_model="policy_engine",
                latency_ms=latency_ms,
            )
            event = Event(
                session_id=session_id,
                agent_id=resolved_agent_id,
                agent_is_registered=is_registered,
                agent_goal=agent_goal,
                action=action,
                assessment=assessment,
                decision=Decision.BLOCK,
                policy_violation=abac_violation,
                provenance=provenance_tags,
                framework=framework,
            )
            await self._ledger.append(event)
            async with self._stats_lock:
                self._session_stats[session_id]["actions"] += 1
                self._session_stats[session_id]["blocked"] += 1
            log.warning("action_blocked_abac", detail=abac_violation.detail)
            return Decision.BLOCK, event

        # 3.5. Provenance check — block actions driven by denied source types
        # (MITRE ATLAS AML.T0054: Prompt Injection via Tool Outputs)
        prov_decision, prov_violation = self._policy.evaluate_provenance(provenance_tags)
        if prov_decision == Decision.BLOCK and prov_violation is not None:
            latency_ms = (time.monotonic() - t_start) * 1000
            assessment = RiskAssessment(
                risk_score=0.90,
                reason=prov_violation.detail,
                indicators=["untrusted_provenance"],
                is_goal_aligned=False,
                analyzer_model="policy_engine",
                latency_ms=latency_ms,
            )
            event = Event(
                session_id=session_id,
                agent_id=resolved_agent_id,
                agent_is_registered=is_registered,
                agent_goal=agent_goal,
                action=action,
                assessment=assessment,
                decision=Decision.BLOCK,
                policy_violation=prov_violation,
                provenance=provenance_tags,
                framework=framework,
            )
            await self._ledger.append(event)
            async with self._stats_lock:
                self._session_stats[session_id]["blocked"] += 1
            log.warning("action_blocked_provenance", detail=prov_violation.detail)
            return Decision.BLOCK, event

        # 4. Deterministic policy enforcement (zero-latency — runs before LLM)
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
            # 5. Intent analysis via Claude (session_context already read under lock above)
            assessment = await self._analyzer.analyze(action, agent_goal, session_context)
            log = log.bind(risk_score=assessment.risk_score)

            # 6. Re-evaluate policy with risk score using demotion-aware thresholds
            if decision != Decision.BLOCK:
                risk_decision, risk_violation = self._policy.evaluate_risk(
                    assessment.risk_score,
                    risk_threshold=risk_threshold,
                    review_threshold=review_threshold,
                )
                if risk_decision == Decision.BLOCK:
                    decision = Decision.BLOCK
                    violation = risk_violation
                elif risk_decision == Decision.REVIEW and decision == Decision.ALLOW:
                    decision = Decision.REVIEW
                    violation = risk_violation

        latency_ms = (time.monotonic() - t_start) * 1000

        event = Event(
            session_id=session_id,
            agent_id=resolved_agent_id,
            agent_is_registered=is_registered,
            agent_goal=agent_goal,
            action=action,
            assessment=assessment,
            decision=decision,
            policy_violation=violation,
            provenance=provenance_tags,
            framework=framework,
        )

        # 6. Log to ledger
        await self._ledger.append(event)

        # 7. Async enrichment — fire-and-forget, zero latency impact
        if decision in (Decision.BLOCK, Decision.REVIEW):
            publisher = get_stream_publisher()
            if publisher.enabled:
                # Redis Streams path: durable, survives worker restarts
                asyncio.create_task(self._publish_to_stream(event, publisher))
            elif get_enrichment_client().enabled:
                # Direct async fallback (no Redis): same process, task-based
                asyncio.create_task(self._enrich_direct(event))

        # 8. Update session counters and history
        # actions counter was pre-incremented atomically in the session limit check.
        async with self._stats_lock:
            if decision == Decision.BLOCK:
                self._session_stats[session_id]["blocked"] += 1
            history = self._session_history[session_id]
            history.append({
                "tool_name": action.tool_name,
                "action_type": action.type.value,
                "decision": decision.value,
            })
            if len(history) > _SESSION_HISTORY_MAX:
                self._session_history[session_id] = history[-_SESSION_HISTORY_MAX:]

        if decision == Decision.BLOCK:
            log.warning("action_blocked", reason=assessment.reason, latency_ms=f"{latency_ms:.1f}ms")
        elif decision == Decision.REVIEW:
            log.warning("action_flagged_for_review", reason=assessment.reason)
        else:
            log.info("action_allowed", latency_ms=f"{latency_ms:.1f}ms")

        return decision, event

    async def _publish_to_stream(self, event: Event, publisher: Any) -> None:
        """Publish event to Redis Stream for enrichment worker to consume."""
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
            # Fallback: enrich directly in-process when Redis is unavailable
            await self._enrich_direct(event)

    async def _enrich_direct(self, event: Event) -> None:
        """Fire-and-forget: enrich event directly via Claude (no Redis)."""
        from agentguard.integrations.insights import get_insights_store

        client = get_enrichment_client()
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
            insight = await client.triage_event(payload)
            store.put(insight)
            logger.info(
                "enrichment_complete",
                event_id=event.event_id,
                attack_patterns=insight.attack_patterns,
                confidence=insight.confidence,
            )
            if insight.attack_patterns:
                from agentguard.taxonomy import lookup_by_attack_pattern
                from agentguard.core.models import AttackTaxonomyAnnotation
                pattern = insight.attack_patterns[0]
                mapping = lookup_by_attack_pattern(pattern)
                annotation = AttackTaxonomyAnnotation(
                    attack_pattern=pattern,
                    mitre_atlas_ids=mapping.atlas_ids,
                    owasp_categories=[c.value for c in mapping.owasp_categories],
                    confidence=insight.confidence,
                )
                await self._ledger.update_event_taxonomy(event.event_id, annotation)
        except Exception as exc:
            logger.warning("enrichment_failed", event_id=event.event_id, error=str(exc))
