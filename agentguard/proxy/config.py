"""Configuration for the LLM API Proxy."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class ProxyConfig(BaseSettings):
    """
    Configuration for the AgentGuard LLM API Proxy.

    All fields are configurable via environment variables with the
    AGENTGUARD_PROXY_ prefix.

    Examples:
        AGENTGUARD_PROXY_PORT=8748
        AGENTGUARD_PROXY_OPENAI_BASE_URL=https://api.openai.com
        AGENTGUARD_PROXY_ANTHROPIC_BASE_URL=https://api.anthropic.com
        AGENTGUARD_PROXY_SCAN_INBOUND=true
        AGENTGUARD_PROXY_INTERCEPT_TOOL_CALLS=true
        AGENTGUARD_PROXY_FAIL_CLOSED=true
        AGENTGUARD_PROXY_GUARDRAIL_MODE=enforce
    """

    model_config = SettingsConfigDict(env_prefix="AGENTGUARD_PROXY_", extra="ignore")

    # Server
    port: int = 8748
    host: str = "0.0.0.0"

    # Upstream providers
    openai_base_url: str = "https://api.openai.com"
    anthropic_base_url: str = "https://api.anthropic.com"

    # Upstream timeouts (seconds)
    upstream_connect_timeout: float = 10.0
    upstream_read_timeout: float = 120.0

    # Feature flags
    scan_inbound: bool = True        # Scan inbound messages with guardrail
    intercept_tool_calls: bool = True  # Intercept LLM-returned tool calls
    fail_closed: bool = True         # Block on unhandled errors

    # Guardrail
    guardrail_mode: str = "enforce"  # "observe" or "enforce"
    # Regex/keyword matching alone can't tell an attack from text that
    # merely discusses the same terminology (see AGENTGUARD_PROXY_GUARDRAIL_
    # DEEP_ANALYSIS=false for the failure mode this caused). Defaulting to
    # True requires a working Anthropic-credentialed deep analyzer backend —
    # see ProxyPipeline startup validation.
    guardrail_deep_analysis: bool = True

    # Identity extraction
    goal_header: str = "X-AgentGuard-Goal"
    session_header: str = "X-AgentGuard-Session"
    agent_id_header: str = "X-AgentGuard-AgentId"
    framework_header: str = "X-AgentGuard-Framework"

    # Policy
    policy_path: str | None = None

    # Logging
    log_level: str = "INFO"
