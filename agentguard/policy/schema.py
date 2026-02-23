"""Pydantic schema for policy YAML configuration."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator


class SessionLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_actions: int = 1000
    max_blocked: int = 50


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = "default"
    risk_threshold: float = Field(default=0.75, ge=0.0, le=1.0)
    review_threshold: float = Field(default=0.60, ge=0.0, le=1.0)
    deny_tools: list[str] = Field(default_factory=list)
    deny_path_patterns: list[str] = Field(default_factory=list)
    deny_domains: list[str] = Field(default_factory=list)
    review_tools: list[str] = Field(default_factory=list)
    allow_tools: list[str] = Field(default_factory=list)
    session_limits: SessionLimits = Field(default_factory=SessionLimits)

    @model_validator(mode="after")
    def validate_thresholds(self) -> "PolicyConfig":
        if self.review_threshold >= self.risk_threshold:
            raise ValueError(
                f"review_threshold ({self.review_threshold}) must be less than "
                f"risk_threshold ({self.risk_threshold})"
            )
        return self

    @classmethod
    def from_yaml(cls, path: str) -> "PolicyConfig":
        import yaml

        with open(path) as f:
            data = yaml.safe_load(f)
        # Support both top-level and nested under "policy" key
        policy_data = data.get("policy", data)
        return cls(**policy_data)
