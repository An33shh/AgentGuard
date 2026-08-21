"""Core AgentGuard interception pipeline: normalize → analyze → enforce → log."""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any

import structlog

from agentguard.core.models import (
    Action,
    ActionType,
    Decision,
    Event,
    ProvenanceTag,
    RiskAssessment,
    derive_agent_id,
)
from agentguard.hardening.approval import ApprovalAuthority, ApprovalError
from agentguard.hardening.models import ActionApproval
from agentguard.integrations.enrichment import get_enrichment_client
from agentguard.integrations.stream import get_stream_publisher
from agentguard.interceptor.action_types import (
    extract_file_path,
    infer_action_type,
    is_credential_path,
)
from agentguard.interceptor.session_tracker import SessionTracker

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
        approval_authority: ApprovalAuthority | None = None,
        approval_ttl_seconds: int = 30,
        session_tracker: SessionTracker | None = None,
    ) -> None:
        self._analyzer = analyzer
        self._policy = policy_engine
        self._ledger = event_ledger
        # Per-session action/blocked counters + history for session_limits
        # enforcement and multi-step attack detection. Redis-backed (shared
        # across replicas) when REDIS_URL is configured, in-memory fallback
        # otherwise — see session_tracker.py's module docstring for why this
        # used to be a plain in-memory dict here and what that broke.
        # A fresh SessionTracker() (not the module-level singleton) by
        # default: Interceptor itself is already constructed once per
        # process behind an lru_cache at every real call site, so this is
        # still exactly one tracker per process in production, while each
        # test's own Interceptor() still gets fully isolated in-memory
        # fallback state instead of sharing one global tracker across tests.
        self._tracker = session_tracker or SessionTracker(history_max=_SESSION_HISTORY_MAX)
        # Paper-2 hardening: per-action signed approval binding (optional, opt-in)
        self._approval_authority = approval_authority
        self._approval_ttl_seconds = approval_ttl_seconds
        self._pending_approvals: dict[str, ActionApproval] = {}

    async def intercept(
        self,
        raw_payload: dict[str, Any],
        agent_goal: str,
        session_id: str | None = None,
        agent_id: str | None = None,
        provenance: dict[str, Any] | None = None,
        provenance_tags: list[ProvenanceTag] | None = None,
        framework: str = "unknown",
        correlation_id: str = "",
        initiating_principal: str = "",
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
                correlation_id=correlation_id,
                initiating_principal=initiating_principal,
            )
        except Exception as exc:
            # Fail-closed: an unhandled error in the pipeline must never silently
            # allow an action through. Block and log the error for investigation.
            latency_ms = (time.monotonic() - t_start) * 1000
            log.exception(
                "intercept_pipeline_error",
                error=str(exc),
                error_type=type(exc).__name__,
                latency_ms=f"{latency_ms:.1f}ms",
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

    def get_approval_token(self, approval_id: str) -> str | None:
        """Retrieve the signed token for a pending approval, if hardening is enabled."""
        approval = self._pending_approvals.get(approval_id)
        return approval.token if approval else None

    async def get_session_stats(self, session_id: str) -> dict[str, Any]:
        """
        Inspect a session's action/blocked counters and whether either
        session_limits lockout condition has locked it out.

        Neither max_actions nor max_blocked has a time window or decay —
        once either is reached, evaluate_session_limits (policy/engine.py)
        blocks every subsequent action for that session_id forever, with no
        automatic recovery. This (plus reset_session below) is the only way
        to see or clear that state short of restarting the whole process
        (or, now that this is Redis-backed when configured, short of an
        explicit reset — a process restart alone no longer clears it).
        """
        stats = await self._tracker.get_stats(session_id)
        limits = self._policy.config.session_limits
        demotion = self._policy.config.demotion
        # A code-review finding: this used to check max_blocked only, but
        # evaluate_session_limits blocks on EITHER max_actions or
        # max_blocked — so a session locked out via max_actions reported
        # locked_out=False here, defeating the point of a diagnostic
        # endpoint built specifically to explain lockouts.
        actions_exhausted = bool(limits.max_actions and stats["actions"] >= limits.max_actions)
        blocked_exhausted = bool(limits.max_blocked and stats["blocked"] >= limits.max_blocked)
        locked_out_reason: str | None = None
        if actions_exhausted:
            locked_out_reason = "max_actions"
        elif blocked_exhausted:
            locked_out_reason = "max_blocked"
        return {
            "session_id": session_id,
            "actions": stats["actions"],
            "blocked": stats["blocked"],
            "max_actions": limits.max_actions,
            "max_blocked": limits.max_blocked,
            "locked_out": actions_exhausted or blocked_exhausted,
            "locked_out_reason": locked_out_reason,
            "demoted": bool(
                demotion.enabled and stats["blocked"] >= demotion.trigger_blocked_count
            ),
        }

    async def reset_session(self, session_id: str) -> bool:
        """
        Clear a session's action/blocked counters and history, lifting a
        max_blocked lockout or demotion for it. Returns False if the
        session had no recorded state to reset.
        """
        return await self._tracker.reset(session_id)

    async def verify_execution(
        self,
        approval_id: str,
        tool_name: str,
        parameters: dict[str, Any],
        session_id: str,
        correlation_id: str,
    ) -> None:
        """
        Second, independent verification pass at the point of actual tool
        execution — the counterpart to the approval issued at decision time.
        Consumes the approval's nonce, so it can only succeed once.

        Raises ApprovalError if hardening isn't configured on this
        Interceptor, the approval is unknown or already consumed, or
        verification fails for any other reason (expiry, action-hash
        mismatch, session/correlation mismatch, replay).
        """
        if self._approval_authority is None:
            raise ApprovalError("Hardening is not enabled on this Interceptor")
        approval = self._pending_approvals.pop(approval_id, None)
        if approval is None:
            raise ApprovalError(f"No pending approval for approval_id={approval_id}")
        await self._approval_authority.verify_and_consume(
            token=approval.token,
            tool_name=tool_name,
            parameters=parameters,
            session_id=session_id,
            correlation_id=correlation_id,
        )

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
        correlation_id: str = "",
        initiating_principal: str = "",
    ) -> tuple[Decision, Event]:

        # 1. Normalize — use framework-appropriate normalizer
        if framework == "openai" and "function" in raw_payload:
            action = ActionNormalizer.from_openai_tool_call(raw_payload)
        else:
            action = ActionNormalizer.from_dict(raw_payload)

        log = log.bind(action_id=action.action_id, tool=action.tool_name, action_type=action.type.value)
        log.info("intercepting_action")

        # 2. Session limits (zero-latency, before any other rule)
        # Atomically check limits and reserve the action slot via the
        # SessionTracker — Redis-backed across replicas when REDIS_URL is
        # configured, in-memory + asyncio.Lock otherwise. Closes the TOCTOU
        # window that would otherwise let concurrent requests bypass
        # max_actions/max_blocked — now across processes too, not just
        # within one (see session_tracker.py's module docstring for why
        # that gap mattered: multiple proxy/API replicas used to each
        # enforce their own independent in-memory counters).
        limits = self._policy.config.session_limits
        limited, current_actions, current_blocked = await self._tracker.reserve_action_slot(
            session_id, limits.max_actions or 0, limits.max_blocked or 0,
        )
        session_context = await self._tracker.get_history(session_id)
        # `limited` is the tracker's own atomic decision and must be
        # trusted directly, NOT re-derived by calling evaluate_session_limits
        # again here: when the reservation succeeds, the returned
        # current_actions is the POST-increment count (the reserve already
        # bumped it), so re-checking `current_actions >= max_actions`
        # against that post-increment value would immediately see the just
        # -crossed threshold and spuriously report BLOCK for a request the
        # tracker had already correctly allowed. (Caught by
        # test_session_max_actions_enforced: an off-by-one where the 3rd
        # of 3 permitted calls, 2->3, got blocked instead of allowed,
        # because evaluate_session_limits(3, 0) sees 3 >= 3 immediately
        # after the reservation itself performed that same 2->3 increment.)
        # evaluate_session_limits is only called to recover the
        # human-readable PolicyViolation (rule_name/detail) when the
        # tracker DID block — its pre-check counts are exactly what's
        # returned in that branch (see reserve_action_slot's docstring),
        # so it reconstructs the same decision, not a different one.
        if limited:
            session_decision, session_violation = self._policy.evaluate_session_limits(
                current_actions, current_blocked
            )
        else:
            session_decision, session_violation = Decision.ALLOW, None
        # current_blocked is the same snapshot the tracker's atomic reserve
        # read the limit check against — using it here (rather than a fresh
        # read) keeps the demotion/effective-thresholds calculation
        # consistent with the decision above instead of racing a concurrent
        # request that's since changed it.
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
            asyncio.create_task(self._ledger.append(event))
            # Session limit hit: still count both action + blocked. The
            # atomic reserve above deliberately didn't increment actions
            # for a request it's blocking (nothing to reserve), so it's
            # recorded here instead, after the fact.
            await self._tracker.increment_actions(session_id)
            await self._tracker.increment_blocked(session_id)
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
            asyncio.create_task(self._ledger.append(event))
            # actions counter was already incremented atomically in the
            # session limit check above (step 2) — only blocked needs
            # bumping here, matching the provenance-block and
            # end-of-pipeline paths. Incrementing actions again here
            # double-counted every ABAC block, inflating this session's
            # actions count 2x per block and triggering
            # session_limits.max_actions roughly twice as early as
            # intended.
            await self._tracker.increment_blocked(session_id)
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
            asyncio.create_task(self._ledger.append(event))
            await self._tracker.increment_blocked(session_id)
            log.warning("action_blocked_provenance", detail=prov_violation.detail)
            return Decision.BLOCK, event

        # 4. Deterministic policy enforcement (zero-latency — runs before LLM)
        decision, violation = self._policy.evaluate(action)

        if decision == Decision.BLOCK and violation is not None:
            # Fast-path: blocked by deterministic rule, skip LLM call
            latency_ms = (time.monotonic() - t_start) * 1000
            if violation.rule_type == "shell_destructive_pattern":
                fast_path_score = self._policy.config.shell_command_policy.block_score
            elif action.type == ActionType.CREDENTIAL_ACCESS:
                fast_path_score = 0.95
            else:
                fast_path_score = 0.80
            assessment = RiskAssessment(
                risk_score=fast_path_score,
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
            correlation_id=correlation_id or str(uuid.uuid4()),
            initiating_principal=initiating_principal,
        )

        # 5.5. Issue a per-action signed approval, binding this exact action
        # instance (tool + params) to the session/correlation chain that
        # allowed it. Only ALLOW decisions get one — nothing executes on
        # REVIEW or BLOCK, so there's nothing to bind an approval to.
        if self._approval_authority is not None and decision == Decision.ALLOW:
            approval = self._approval_authority.issue(
                tool_name=action.tool_name,
                parameters=action.parameters,
                session_id=session_id,
                correlation_id=event.correlation_id,
                ttl_seconds=self._approval_ttl_seconds,
            )
            event.approval_id = approval.approval_id
            self._pending_approvals[approval.approval_id] = approval

        # 6. Log to ledger — fire-and-forget, off the critical path
        asyncio.create_task(self._ledger.append(event))

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
        # actions counter was already incremented atomically in the session limit check.
        if decision == Decision.BLOCK:
            await self._tracker.increment_blocked(session_id)
        await self._tracker.append_history(session_id, {
            "tool_name": action.tool_name,
            "action_type": action.type.value,
            "decision": decision.value,
        })

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
                from agentguard.core.models import AttackTaxonomyAnnotation
                from agentguard.taxonomy import lookup_by_attack_pattern
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
