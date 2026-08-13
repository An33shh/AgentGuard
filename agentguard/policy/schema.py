"""Pydantic schema for policy YAML configuration."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator


class SessionLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_actions: int = 1000
    max_blocked: int = 50


class DemotionConfig(BaseModel):
    """
    Dynamic session demotion — automatically tightens thresholds for
    sessions that have accumulated multiple blocked events.

    When a session reaches trigger_blocked_count blocks, its effective
    risk_threshold drops to demoted_risk_threshold and review_threshold
    drops to demoted_review_threshold. No restart required.

    NOTE: trigger_blocked_count counts ALL block types — deny_tools, path
    patterns, ABAC violations, risk-threshold blocks, and session limits.
    This is intentional: any sign of hostile behavior tightens the thresholds.
    """
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    trigger_blocked_count: int = Field(default=3, ge=1)
    demoted_risk_threshold: float = Field(default=0.50, ge=0.0, le=1.0)
    demoted_review_threshold: float = Field(default=0.35, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def validate_demoted_thresholds(self) -> DemotionConfig:
        if self.demoted_review_threshold >= self.demoted_risk_threshold:
            raise ValueError(
                f"demoted_review_threshold ({self.demoted_review_threshold}) must be less than "
                f"demoted_risk_threshold ({self.demoted_risk_threshold})"
            )
        return self


class ShellCommandPolicy(BaseModel):
    """
    Deterministic destructive-command pre-screen.

    Replaces blanket deny_tools:[bash]-style bans in the default policy: an
    operator who genuinely wants "no agent ever runs Bash" can still express
    that via deny_tools (unchanged, still fully supported — see
    policies/strict.yaml). This is instead a content-aware fast path that
    blocks objectively dangerous command patterns (rm -rf, fork bombs, etc.)
    without blanket-denying the tool, while anything that doesn't match
    still falls through to the existing LLM-based risk scoring.

    Scans every parameter value on every action, not just SHELL_COMMAND-
    classified ones — a pentest found ActionType gating a full bypass (any
    tool/parameter naming outside the classifier's hardcoded lexicon evades
    it entirely). See agentguard/policy/engine.py's Rule 1.5 comment.
    """
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    deny_patterns: list[str] = Field(
        default_factory=list,
        description="Regex patterns to block. Empty list uses the built-in defaults in agentguard.analyzer.patterns.",
    )
    block_score: float = Field(
        default=0.90,
        ge=0.0,
        le=1.0,
        description=(
            "risk_score attached to the synthesized fast-path RiskAssessment "
            "when this rule fires — mirrors LocalClassifier.INJECTION_SCORE's "
            "role, not a confidence filter on which patterns block (every "
            "pattern in deny_patterns/the built-in set always blocks on "
            "match, regardless of this value)."
        ),
    )


class RuleAnnotation(BaseModel):
    """
    Optional per-rule MITRE ATLAS / OWASP annotation override in policy YAML.

    Keys in PolicyConfig.rule_annotations correspond to rule_name values
    used in PolicyViolation (e.g. "deny_tools", "credential_access").
    Annotations are merged (union) with auto-detected taxonomy — they add
    to, never replace, the defaults from RULE_TYPE_TO_TAXONOMY.
    """
    model_config = ConfigDict(extra="forbid")

    mitre_atlas_ids: list[str] = Field(default_factory=list)
    owasp_categories: list[str] = Field(default_factory=list)
    notes: str = ""


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
    shell_command_policy: ShellCommandPolicy = Field(default_factory=ShellCommandPolicy)

    # ABAC: tools that require a registered agent identity
    deny_unregistered_tools: list[str] = Field(
        default_factory=list,
        description="Tools blocked for unregistered (auto-detected) agents.",
    )

    # Provenance-based blocking (MITRE ATLAS AML.T0054)
    deny_provenance_sources: list[str] = Field(
        default_factory=list,
        description=(
            "Block actions whose provenance includes these source types. "
            "Values are ProvenanceSourceType strings: 'external_data', 'tool_output', etc. "
            "Supports fnmatch wildcards, e.g. '*_data'."
        ),
    )

    # Dynamic session demotion
    demotion: DemotionConfig = Field(default_factory=DemotionConfig)

    # Phase 8: optional per-rule MITRE ATLAS / OWASP annotation overrides
    rule_annotations: dict[str, RuleAnnotation] = Field(
        default_factory=dict,
        description=(
            "Optional per-rule taxonomy annotation overrides. "
            "Keys are rule_names as used in PolicyViolation.rule_name. "
            "Merged (union) with auto-detected annotations from the taxonomy module."
        ),
    )

    @model_validator(mode="after")
    def validate_thresholds(self) -> PolicyConfig:
        if self.review_threshold >= self.risk_threshold:
            raise ValueError(
                f"review_threshold ({self.review_threshold}) must be less than "
                f"risk_threshold ({self.risk_threshold})"
            )
        return self

    @classmethod
    def from_yaml(cls, path: str) -> PolicyConfig:
        import yaml

        with open(path) as f:
            data = yaml.safe_load(f)
        policy_data = data.get("policy", data)
        return cls(**policy_data)
