"""Core Pydantic models for AgentGuard."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ActionType(str, Enum):
    TOOL_CALL = "tool_call"
    SHELL_COMMAND = "shell_command"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    HTTP_REQUEST = "http_request"
    MEMORY_WRITE = "memory_write"
    CREDENTIAL_ACCESS = "credential_access"
    UNKNOWN = "unknown"


class Decision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REVIEW = "review"


class Action(BaseModel):
    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: ActionType = ActionType.UNKNOWN
    tool_name: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = {"use_enum_values": False}


class RiskAssessment(BaseModel):
    risk_score: float = Field(ge=0.0, le=1.0)
    reason: str
    indicators: list[str] = Field(default_factory=list)
    is_goal_aligned: bool = True
    analyzer_model: str = "unknown"
    latency_ms: float = 0.0

    @field_validator("risk_score")
    @classmethod
    def clamp_score(cls, v: float) -> float:
        return max(0.0, min(1.0, v))

    @property
    def risk_level(self) -> str:
        if self.risk_score < 0.3:
            return "low"
        elif self.risk_score < 0.6:
            return "medium"
        elif self.risk_score < 0.75:
            return "high"
        else:
            return "critical"


class PolicyViolation(BaseModel):
    rule_name: str
    rule_type: str
    detail: str
    decision: Decision


class Event(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    agent_goal: str
    action: Action
    assessment: RiskAssessment
    decision: Decision
    policy_violation: PolicyViolation | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    provenance: dict[str, Any] = Field(default_factory=dict)
    framework: str = "unknown"


class TimelineSummary(BaseModel):
    session_id: str
    total_events: int
    blocked_events: int
    reviewed_events: int
    allowed_events: int
    max_risk_score: float
    avg_risk_score: float
    start_time: datetime | None = None
    end_time: datetime | None = None
    attack_vectors: list[str] = Field(default_factory=list)
