"""Data models for PromptGuardrail — inbound LLM traffic inspection."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict


class GuardrailVerdict(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"  # Replace sensitive spans, let prompt through


class ContextType(str, Enum):
    USER_INPUT = "user_input"
    TOOL_RESPONSE = "tool_response"
    EXTERNAL_DATA = "external_data"  # Web pages, files, API responses — highest risk
    SYSTEM = "system"


class GuardrailMode(str, Enum):
    OBSERVE = "observe"  # Log only, never block — for gradual rollout
    ENFORCE = "enforce"  # Block or redact


class DetectionCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    CREDENTIAL = "credential"
    PII = "pii"
    JAILBREAK = "jailbreak"


class GuardrailDetection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: DetectionCategory
    pattern_name: str
    matched_snippet: str  # Max 80 chars, for logging
    start_offset: int
    end_offset: int
    confidence: float


class GuardrailResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    verdict: GuardrailVerdict
    context_type: ContextType
    mode: GuardrailMode  # Mode that was active — callers need this to understand the verdict
    detections: list[GuardrailDetection]
    redacted_text: str | None  # Populated only when verdict=REDACT
    analyzer_model: str  # "local_scanner" or Claude model name
    latency_ms: float
    timestamp: datetime


class GuardrailEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    session_id: str
    agent_id: str
    result: GuardrailResult
    text_hash: str  # SHA-256 hex of original text — not stored raw
    text_length: int
    timestamp: datetime


class GuardrailConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: GuardrailMode = GuardrailMode.OBSERVE
    deep_analysis: bool = False
    deep_analysis_model: str = "claude-sonnet-4-6"
    deep_analysis_api_key: str | None = None
    block_threshold: float = 0.80
    redact_threshold: float = 0.50
    scan_injection: bool = True
    scan_credentials: bool = True
    scan_pii: bool = True
    max_text_length: int = 50_000
