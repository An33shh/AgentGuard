"""
Language-agnostic intercept endpoint.

Any runtime (Node.js, Go, OpenClaw, etc.) can POST a tool call here
and get back a decision before executing it.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from agentguard.core.models import ProvenanceSourceType, ProvenanceTag
from api.dependencies import InterceptorDep

router = APIRouter(prefix="/api/v1/intercept", tags=["intercept"])


class InterceptRequest(BaseModel):
    tool_name: str = Field(..., description="Name of the tool about to be called")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Tool parameters")
    goal: str = Field(..., description="Agent's declared purpose for this session")
    session_id: str = Field(default_factory=lambda: uuid.uuid4().hex, description="Session identifier")
    agent_id: str | None = Field(
        None,
        description=(
            "Self-asserted agent identity (optional). Unverified — carried "
            "through for audit/correlation only, never used to grant "
            "registered-agent ABAC privileges (deny_unregistered_tools)."
        ),
    )
    framework: str = Field("api", description="Calling framework identifier")


class InterceptResponse(BaseModel):
    decision: str  # "allow" | "block" | "review"
    risk_score: float
    reason: str
    event_id: str
    session_id: str
    mitre_technique: str | None = None
    owasp_category: str | None = None
    policy_rule: str | None = None


@router.post("", response_model=InterceptResponse)
async def intercept_tool_call(body: InterceptRequest, interceptor: InterceptorDep) -> InterceptResponse:
    """
    Evaluate a tool call against AgentGuard's policy + intent analyzer.

    Returns the decision immediately. The caller is responsible for honouring
    a ``block`` decision by not executing the tool.

    This endpoint is the integration point for non-Python runtimes (Node.js,
    TypeScript, Go) and for OpenClaw ClawHub skills.
    """
    raw_payload = {"tool_name": body.tool_name, "parameters": body.parameters}

    # agent_id intentionally NOT forwarded to Interceptor.intercept()'s
    # agent_id param. This is an unauthenticated JSON body field — any
    # caller can claim any string, and forwarding it flips
    # is_registered=True (interceptor.py), which skips the
    # deny_unregistered_tools ABAC rule entirely (policy/engine.py). A
    # pentest confirmed this: {"tool_name": "git.push", "agent_id": "x"}
    # bypassed deny_unregistered_tools completely. Same fix already applied
    # to the proxy's X-AgentGuard-AgentId header — see
    # agentguard/proxy/pipeline.py's _intercept_single. Until this endpoint
    # has a real, operator-vetted agent-registration mechanism, a claimed
    # agent_id is carried only as an unverified provenance tag — never as
    # enforcement-relevant identity.
    provenance_tags = []
    if body.agent_id:
        provenance_tags.append(ProvenanceTag(
            source_type=ProvenanceSourceType.SYSTEM,
            label="intercept_api_claimed_agent_id_unverified",
            value=body.agent_id[:80],
        ))

    decision, event = await interceptor.intercept(
        raw_payload=raw_payload,
        agent_goal=body.goal,
        session_id=body.session_id,
        provenance_tags=provenance_tags,
        framework=body.framework,
    )

    # RiskAssessment has no mitre_technique/owasp_category/policy_rule
    # fields directly — those live on Event.policy_violation (populated
    # synchronously by the deterministic policy engine, for policy-driven
    # decisions) or, for LLM-scored decisions, would eventually land on
    # assessment.attack_taxonomy — except enrichment that populates it runs
    # fire-and-forget via asyncio.create_task() AFTER this response is
    # already built (see Interceptor._intercept_inner), so it's never
    # populated yet at this point regardless of decision path. policy_violation
    # is therefore the only synchronously-reliable source here.
    violation = event.policy_violation
    return InterceptResponse(
        decision=decision.value,
        risk_score=event.assessment.risk_score,
        reason=event.assessment.reason,
        event_id=str(event.event_id),
        session_id=body.session_id,
        mitre_technique=violation.mitre_atlas_ids[0] if violation and violation.mitre_atlas_ids else None,
        owasp_category=violation.owasp_categories[0] if violation and violation.owasp_categories else None,
        policy_rule=violation.rule_name if violation else None,
    )
