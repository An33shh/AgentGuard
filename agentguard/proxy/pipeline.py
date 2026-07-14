"""
ProxyPipeline — core orchestrator for the LLM API Proxy.

Flow:
  1. Extract inbound text segments from the request.
  2. Scan each segment with PromptGuardrail (fast, zero-LLM-cost in enforce mode).
  3. If any segment is BLOCK → return blocked response immediately.
  4. Forward the (normalized) request to the real LLM.
  5. Extract tool calls from the LLM response.
  6. Run each tool call concurrently through AgentGuard's Interceptor pipeline.
  7. Build and return the final response:
     a. All allowed  → return original response unchanged.
     b. Some blocked → return modified response with blocked calls removed + explanation injected.
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from agentguard.core.models import Decision, ProvenanceSourceType, ProvenanceTag
from agentguard.guardrail.models import ContextType, GuardrailVerdict
from agentguard.proxy.format_handler import LLMFormatHandler
from agentguard.proxy.models import (
    ProxyInterceptionResult,
    ProxyRequestContext,
)

if False:  # TYPE_CHECKING without import
    from agentguard.guardrail.guardrail import PromptGuardrail
    from agentguard.interceptor.interceptor import Interceptor

logger = structlog.get_logger(__name__)


class ProxyPipeline:
    """
    Orchestrates inbound scanning + tool call interception for a single
    proxied LLM request.
    """

    def __init__(
        self,
        interceptor: "Interceptor",
        guardrail: "PromptGuardrail | None",
        scan_inbound: bool = True,
        intercept_tool_calls: bool = True,
    ) -> None:
        self._interceptor = interceptor
        self._guardrail = guardrail
        self._scan_inbound = scan_inbound
        self._intercept_tool_calls = intercept_tool_calls

    async def handle_request(
        self,
        body: dict[str, Any],
        upstream_headers: dict[str, str],
        handler: LLMFormatHandler,
        context: ProxyRequestContext,
        upstream_call: Any,  # async callable(normalized_body, headers) -> (response_body, status)
    ) -> tuple[dict[str, Any], int]:
        """
        Full proxy pipeline.

        Returns (response_body, status_code).
        """
        # ---- Step 1+2: Inbound scan ----------------------------------------
        if self._scan_inbound and self._guardrail is not None:
            block_reason = await self._scan_inbound_texts(body, handler, context)
            if block_reason:
                model = body.get("model", "unknown")
                blocked_body = handler.build_inbound_block_response(block_reason, model)
                logger.warning(
                    "proxy_inbound_blocked",
                    session_id=context.session_id,
                    agent_goal=context.agent_goal[:80],
                    reason=block_reason,
                )
                return blocked_body, 200  # 200 so the agent loop doesn't crash

        # ---- Step 3: Normalize + forward -----------------------------------
        normalized = handler.normalize_request(body)
        response_body, status_code = await upstream_call(normalized, upstream_headers)

        if status_code != 200:
            return response_body, status_code

        # ---- Step 4+5: Tool call interception ------------------------------
        if self._intercept_tool_calls:
            tool_calls = handler.extract_tool_calls(response_body)
            if tool_calls:
                results = await self._intercept_tool_calls_concurrent(tool_calls, context)
                blocked = [r for r in results if not r.allowed]
                if blocked:
                    allowed = [r for r in results if r.allowed]
                    response_body = handler.build_blocked_response(
                        response_body, blocked, allowed
                    )
                    logger.warning(
                        "proxy_tool_calls_blocked",
                        session_id=context.session_id,
                        blocked=[r.tool_call.name for r in blocked],
                        allowed=[r.tool_call.name for r in allowed],
                    )

        return response_body, status_code

    async def _scan_inbound_texts(
        self,
        body: dict[str, Any],
        handler: LLMFormatHandler,
        context: ProxyRequestContext,
    ) -> str | None:
        """
        Scan all inbound text segments.

        Returns the block reason string if any segment should be blocked,
        or None if everything is clean.
        """
        targets = handler.extract_inbound_texts(body)
        if not targets:
            return None

        # Scan concurrently — each segment is independent
        tasks = [
            self._guardrail.scan(t.text, ContextType.USER_INPUT if t.role in ("user", "system") else ContextType.TOOL_RESPONSE)
            for t in targets
        ]
        results = await asyncio.gather(*tasks)

        for target, result in zip(targets, results):
            if result.verdict == GuardrailVerdict.BLOCK:
                detections = [d.pattern_name for d in result.detections]
                return (
                    f"Inbound {target.role!r} message (index={target.message_index}) "
                    f"contains a security threat: {detections}"
                )

        return None

    async def _intercept_tool_calls_concurrent(
        self,
        tool_calls: list,
        context: ProxyRequestContext,
    ) -> list[ProxyInterceptionResult]:
        """Run all tool calls through the Interceptor concurrently."""
        tasks = [
            self._intercept_single(tc, context)
            for tc in tool_calls
        ]
        return await asyncio.gather(*tasks)

    async def _intercept_single(
        self,
        tool_call: Any,
        context: ProxyRequestContext,
    ) -> ProxyInterceptionResult:
        raw_payload = {
            "tool_name": tool_call.name,
            "parameters": tool_call.arguments,
        }
        try:
            decision, event = await self._interceptor.intercept(
                raw_payload=raw_payload,
                agent_goal=context.agent_goal,
                session_id=context.session_id,
                provenance_tags=[
                    ProvenanceTag(
                        source_type=ProvenanceSourceType.SYSTEM,
                        label="llm_proxy",
                        value=context.agent_goal[:80],
                    )
                ],
                framework=context.framework,
                correlation_id=context.correlation_id,
                initiating_principal=context.initiating_principal,
            )
            allowed = decision != Decision.BLOCK
            reason = event.assessment.reason if not allowed else ""
            risk_score = event.assessment.risk_score
        except Exception as exc:
            logger.error("proxy_intercept_error", tool=tool_call.name, error=str(exc))
            # Fail closed — unknown error → block
            allowed = False
            reason = f"Internal error during interception: {type(exc).__name__}"
            risk_score = 1.0

        return ProxyInterceptionResult(
            tool_call=tool_call,
            allowed=allowed,
            reason=reason,
            risk_score=risk_score,
        )
