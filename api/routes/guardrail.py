"""Guardrail endpoint — scan inbound text for injection, credentials, and PII."""

from __future__ import annotations

import uuid

from fastapi import APIRouter
from pydantic import BaseModel, Field

from agentguard.guardrail.models import ContextType, GuardrailMode
from api.dependencies import GuardrailDep

router = APIRouter(prefix="/api/v1/guardrail", tags=["guardrail"])


class GuardrailScanRequest(BaseModel):
    text: str = Field(..., description="Text to scan before sending to agent LLM")
    context_type: ContextType = Field(
        ContextType.USER_INPUT,
        description="Source context: user_input | tool_response | external_data | system",
    )
    session_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    agent_id: str | None = None
    mode: GuardrailMode | None = Field(
        None,
        description="Override server default: observe | enforce",
    )


class GuardrailDetectionOut(BaseModel):
    category: str
    pattern_name: str
    matched_snippet: str
    confidence: float


class GuardrailScanResponse(BaseModel):
    scan_id: str
    verdict: str  # allow | block | redact
    mode: str  # observe | enforce
    context_type: str
    detections: list[GuardrailDetectionOut]
    redacted_text: str | None
    analyzer_model: str
    latency_ms: float


@router.post("/scan", response_model=GuardrailScanResponse)
async def scan_prompt(body: GuardrailScanRequest, guardrail: GuardrailDep) -> GuardrailScanResponse:
    """
    Scan text for prompt injection, credential leaks, and PII before it reaches the agent LLM.

    Returns:
    - ``allow`` — text is safe to use
    - ``block`` — injection/jailbreak detected; discard the text
    - ``redact`` — credentials/PII found; use ``redacted_text`` instead

    In ``observe`` mode the verdict is always ``allow`` but detections are logged.
    """
    result = await guardrail.scan(body.text, body.context_type, body.mode)

    return GuardrailScanResponse(
        scan_id=result.scan_id,
        verdict=result.verdict.value,
        mode=result.mode.value,
        context_type=result.context_type.value,
        detections=[
            GuardrailDetectionOut(
                category=d.category.value,
                pattern_name=d.pattern_name,
                matched_snippet=d.matched_snippet,
                confidence=d.confidence,
            )
            for d in result.detections
        ],
        redacted_text=result.redacted_text,
        analyzer_model=result.analyzer_model,
        latency_ms=result.latency_ms,
    )
