"""PromptGuardrail — inbound LLM traffic inspection.

Scans text BEFORE it reaches an AI agent's LLM.
Detects prompt injection, credential leaks, and PII.

Standalone component — no dependency on Interceptor, PolicyEngine, or IntentAnalyzer.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import time
import uuid
from datetime import datetime, timezone

import structlog

from agentguard.guardrail.ledger import GuardrailLedger, InMemoryGuardrailLedger
from agentguard.guardrail.local_scanner import LocalScanner
from agentguard.guardrail.models import (
    ContextType,
    DetectionCategory,
    GuardrailConfig,
    GuardrailDetection,
    GuardrailEvent,
    GuardrailMode,
    GuardrailResult,
    GuardrailVerdict,
)

logger = structlog.get_logger(__name__)

_INJECTION_CATEGORIES = {DetectionCategory.PROMPT_INJECTION, DetectionCategory.JAILBREAK}
# High-confidence threshold for local detections to skip deep analysis
_LOCAL_HIGH_CONFIDENCE = 0.90


class PromptGuardrail:
    """
    Scans inbound text for injection attacks, credential leaks, and PII.

    Usage (observe mode — log only, never block):
        guardrail = PromptGuardrail.from_env(mode="observe")
        result = await guardrail.scan(user_message, ContextType.USER_INPUT)

    Usage (enforce mode — block or redact):
        guardrail = PromptGuardrail.from_env(mode="enforce")
        result = await guardrail.scan(web_page_content, ContextType.EXTERNAL_DATA)
        if result.verdict == GuardrailVerdict.BLOCK:
            raise ValueError("Blocked: prompt injection detected")
        text_to_use = result.redacted_text or web_page_content
    """

    def __init__(
        self,
        config: GuardrailConfig,
        ledger: GuardrailLedger | None = None,
        session_id: str | None = None,
        agent_id: str = "",
    ) -> None:
        self._config = config
        self._ledger = ledger or InMemoryGuardrailLedger()
        self._session_id = session_id or uuid.uuid4().hex
        self._agent_id = agent_id
        self._scanner = LocalScanner()
        self._deep = None
        if config.deep_analysis:
            from agentguard.guardrail.deep_analyzer import DeepAnalyzer
            self._deep = DeepAnalyzer(
                api_key=config.deep_analysis_api_key,
                model=config.deep_analysis_model,
            )

    @classmethod
    def from_env(
        cls,
        mode: str = "observe",
        deep_analysis: bool = False,
        ledger: GuardrailLedger | None = None,
        session_id: str | None = None,
        agent_id: str = "",
    ) -> "PromptGuardrail":
        """Create from environment variables."""
        resolved_mode = GuardrailMode(
            os.getenv("AGENTGUARD_GUARDRAIL_MODE", mode)
        )
        resolved_deep = (
            os.getenv("AGENTGUARD_GUARDRAIL_DEEP", "false").lower() == "true"
            or deep_analysis
        )
        api_key = os.getenv("ANTHROPIC_API_KEY")
        config = GuardrailConfig(
            mode=resolved_mode,
            deep_analysis=resolved_deep,
            deep_analysis_api_key=api_key,
        )
        return cls(config=config, ledger=ledger, session_id=session_id, agent_id=agent_id)

    async def scan(
        self,
        text: str,
        context_type: ContextType = ContextType.USER_INPUT,
        mode: GuardrailMode | None = None,
    ) -> GuardrailResult:
        """
        Scan text and return a GuardrailResult.

        Pipeline:
          1. Truncate to max_text_length
          2. LocalScanner — zero cost regex scan
          3. If deep_analysis and no high-confidence local hit → DeepAnalyzer (LLM)
          4. Decide verdict based on detections + context
          5. Observe mode: compute real verdict, log it, but return ALLOW
          6. Fire-and-forget ledger logging
        """
        start = time.monotonic()
        effective_mode = mode or self._config.mode

        # 1. Truncate
        if len(text) > self._config.max_text_length:
            text = text[: self._config.max_text_length]

        # 2. Local scan
        detections = self._scanner.scan(
            text,
            scan_injection=self._config.scan_injection,
            scan_credentials=self._config.scan_credentials,
            scan_pii=self._config.scan_pii,
        )

        analyzer_model = "local_scanner"

        # 3. Optional deep analysis — skip if local already found high-confidence injection
        if self._deep is not None:
            has_high_confidence_local = any(
                d.confidence >= _LOCAL_HIGH_CONFIDENCE and d.category in _INJECTION_CATEGORIES
                for d in detections
            )
            if not has_high_confidence_local:
                try:
                    _, llm_detections, _ = await self._deep.analyze(
                        text, context_type, detections
                    )
                    detections = detections + llm_detections
                    analyzer_model = self._config.deep_analysis_model
                except Exception as exc:
                    logger.warning("guardrail_deep_analysis_failed", error=str(exc))

        # 4. Decide real verdict
        real_verdict = self._decide_verdict(detections, context_type)

        # 5. Build redacted text when verdict is REDACT
        redacted_text: str | None = None
        if real_verdict == GuardrailVerdict.REDACT:
            redacted_text = self._scanner.redact(text, detections)

        # 6. Observe mode override — always return ALLOW but log true verdict
        reported_verdict = real_verdict
        if effective_mode == GuardrailMode.OBSERVE:
            reported_verdict = GuardrailVerdict.ALLOW

        latency_ms = (time.monotonic() - start) * 1000
        now = datetime.now(timezone.utc)

        result = GuardrailResult(
            scan_id=uuid.uuid4().hex,
            verdict=reported_verdict,
            context_type=context_type,
            mode=effective_mode,
            detections=detections,
            redacted_text=redacted_text if reported_verdict == GuardrailVerdict.REDACT else None,
            analyzer_model=analyzer_model,
            latency_ms=round(latency_ms, 2),
            timestamp=now,
        )

        # Fire-and-forget ledger logging
        asyncio.create_task(
            self._log_event(text, result, real_verdict, now)
        )

        if detections:
            logger.info(
                "guardrail_scan",
                verdict=reported_verdict.value,
                true_verdict=real_verdict.value,
                mode=effective_mode.value,
                context_type=context_type.value,
                detections=[d.pattern_name for d in detections],
                latency_ms=round(latency_ms, 1),
            )

        return result

    def _decide_verdict(
        self,
        detections: list[GuardrailDetection],
        context_type: ContextType,
    ) -> GuardrailVerdict:
        """
        Decision logic:
        - Any injection/jailbreak → BLOCK (can't be safely redacted)
        - Credential or PII only → REDACT
        - No detections → ALLOW

        EXTERNAL_DATA and TOOL_RESPONSE have lower confidence thresholds
        (attackers deliberately use these vectors).
        """
        if not detections:
            return GuardrailVerdict.ALLOW

        # Context multiplier: higher-risk sources get stricter thresholds
        threshold_multiplier = (
            0.85
            if context_type in (ContextType.EXTERNAL_DATA, ContextType.TOOL_RESPONSE)
            else 1.0
        )

        for det in detections:
            if det.category in _INJECTION_CATEGORIES:
                effective_confidence = det.confidence * threshold_multiplier
                if effective_confidence >= 0.70:
                    return GuardrailVerdict.BLOCK

        # No injection found — check for credentials/PII
        has_sensitive = any(
            det.category in (DetectionCategory.CREDENTIAL, DetectionCategory.PII)
            for det in detections
        )
        if has_sensitive:
            return GuardrailVerdict.REDACT

        return GuardrailVerdict.ALLOW

    async def _log_event(
        self,
        original_text: str,
        result: GuardrailResult,
        true_verdict: GuardrailVerdict,
        timestamp: datetime,
    ) -> None:
        try:
            text_hash = hashlib.sha256(original_text.encode()).hexdigest()
            # If observe mode suppressed the verdict, log result with true verdict for observability
            log_result = result
            if result.verdict != true_verdict:
                log_result = result.model_copy(update={"verdict": true_verdict})

            event = GuardrailEvent(
                event_id=uuid.uuid4().hex,
                session_id=self._session_id,
                agent_id=self._agent_id,
                result=log_result,
                text_hash=text_hash,
                text_length=len(original_text),
                timestamp=timestamp,
            )
            await self._ledger.append_guardrail_event(event)
        except Exception as exc:
            logger.warning("guardrail_ledger_log_failed", error=str(exc))
