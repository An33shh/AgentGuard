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

from api.dependencies import InterceptorDep

router = APIRouter(prefix="/api/v1/intercept", tags=["intercept"])


class InterceptRequest(BaseModel):
    tool_name: str = Field(..., description="Name of the tool about to be called")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Tool parameters")
    goal: str = Field(..., description="Agent's declared purpose for this session")
    session_id: str = Field(default_factory=lambda: uuid.uuid4().hex, description="Session identifier")
    agent_id: str | None = Field(None, description="Explicit agent identity (optional)")
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

    decision, event = await interceptor.intercept(
        raw_payload=raw_payload,
        agent_goal=body.goal,
        session_id=body.session_id,
        agent_id=body.agent_id,
        framework=body.framework,
    )

    return InterceptResponse(
        decision=decision.value,
        risk_score=event.assessment.risk_score,
        reason=event.assessment.reason,
        event_id=str(event.event_id),
        session_id=body.session_id,
        mitre_technique=event.assessment.mitre_technique,
        owasp_category=event.assessment.owasp_category,
        policy_rule=event.assessment.policy_rule,
    )
