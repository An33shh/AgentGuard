"""LLM provider backends for AgentGuard intent analysis."""

from __future__ import annotations

import os
import re
import warnings

from agentguard.analyzer.backends.base import AnalyzerBackend
from agentguard.analyzer.backends.anthropic_backend import AnthropicBackend
from agentguard.analyzer.backends.openai_compat import OpenAICompatBackend

__all__ = ["AnalyzerBackend", "AnthropicBackend", "OpenAICompatBackend", "create_backend"]

# Default models per provider
_DEFAULT_MODELS: dict[str, str] = {
    "anthropic": "claude-sonnet-4-6",
    "openai": "gpt-4o",
    "ollama": "llama3.1",
    "lm_studio": "local-model",
    "groq": "llama-3.3-70b-versatile",
    "together": "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
}

# Base URLs for known OpenAI-compatible providers
_BASE_URLS: dict[str, str] = {
    "ollama": "http://localhost:11434/v1",
    "lm_studio": "http://localhost:1234/v1",
    "groq": "https://api.groq.com/openai/v1",
    "together": "https://api.together.xyz/v1",
}


def create_backend(
    provider: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
) -> AnalyzerBackend:
    """
    Factory that creates the right backend from config.

    Provider resolution order:
      1. explicit `provider` argument
      2. AGENTGUARD_ANALYZER env var
      3. auto-detect from available API keys (Anthropic → OpenAI → Ollama)

    Examples:
        create_backend("anthropic")
        create_backend("openai", model="gpt-4o-mini")
        create_backend("ollama", model="llama3.1")
        create_backend("openai", base_url="https://api.groq.com/openai/v1")
    """
    provider = provider or os.getenv("AGENTGUARD_ANALYZER") or _auto_detect_provider()
    provider = provider.lower().strip()

    resolved_model = model or os.getenv("AGENTGUARD_MODEL") or _DEFAULT_MODELS.get(provider, "")
    resolved_base_url = base_url or os.getenv("AGENTGUARD_BASE_URL") or _BASE_URLS.get(provider)

    _warn_if_weak_model(provider, resolved_model)

    if provider == "anthropic":
        key = api_key or os.getenv("ANTHROPIC_API_KEY")
        return AnthropicBackend(api_key=key, model=resolved_model)

    # All OpenAI-compatible providers (openai, ollama, lm_studio, groq, together, custom)
    key = api_key or _resolve_openai_compat_key(provider)
    return OpenAICompatBackend(
        api_key=key,
        model=resolved_model,
        base_url=resolved_base_url,
        provider_name=provider,
    )


# Known-weak model substrings — match wins over the strong-model check below.
# This prevents "claude-4-haiku" from slipping through a version-number allowlist.
_WEAK_MODEL_SUBSTRINGS: dict[str, re.Pattern[str]] = {
    "anthropic": re.compile(r"haiku", re.IGNORECASE),
    "openai":    re.compile(r"(gpt-3\.5|o-mini|instruct)", re.IGNORECASE),
    "groq":      re.compile(r"llama.*[38]b|gemma|whisper|guard", re.IGNORECASE),
}

# Strong-model patterns — only consulted when no weak substring matched.
# Conservative: unknown models are not warned about (avoid false positives for new releases).
_STRONG_MODEL_PATTERNS: dict[str, re.Pattern[str]] = {
    # Sonnet (any version), Opus (any version)
    "anthropic": re.compile(r"(sonnet|opus)", re.IGNORECASE),
    # GPT-4 family: gpt-4, gpt-4o, gpt-4-turbo
    "openai":    re.compile(r"gpt-4", re.IGNORECASE),
    # Large open-weight models (70B+)
    "groq":      re.compile(r"(70b|405b)", re.IGNORECASE),
    "together":  re.compile(r"(70b|405b)", re.IGNORECASE),
}

# Local providers where model quality is always unknown
_LOCAL_PROVIDERS = frozenset({"ollama", "lm_studio"})

_RECOMMEND_MSG = (
    "Recommended: claude-sonnet-4-6 (Anthropic) or gpt-4o (OpenAI). "
    "Weaker models may miss sophisticated prompt injection and goal hijacking attacks."
)


def _warn_if_weak_model(provider: str, model: str) -> None:
    """Emit a UserWarning when the configured model may degrade security quality."""
    if provider in _LOCAL_PROVIDERS:
        warnings.warn(
            f"AgentGuard: local model '{model}' via {provider}. "
            f"Security quality depends entirely on model capability. {_RECOMMEND_MSG}",
            UserWarning,
            stacklevel=4,
        )
        return

    # Explicit weak check takes priority — catches "claude-4-haiku", "gpt-4o-mini", etc.
    weak_pattern = _WEAK_MODEL_SUBSTRINGS.get(provider)
    if weak_pattern is not None and weak_pattern.search(model):
        warnings.warn(
            f"AgentGuard: model '{model}' ({provider}) is not recommended for security analysis. "
            f"{_RECOMMEND_MSG}",
            UserWarning,
            stacklevel=4,
        )
        return

    # Unknown models that don't match any strong pattern — warn conservatively
    strong_pattern = _STRONG_MODEL_PATTERNS.get(provider)
    if strong_pattern is not None and not strong_pattern.search(model):
        warnings.warn(
            f"AgentGuard: model '{model}' ({provider}) may not provide reliable adversarial "
            f"reasoning for security analysis. {_RECOMMEND_MSG}",
            UserWarning,
            stacklevel=4,
        )


def _auto_detect_provider() -> str:
    """Detect which provider to use based on available env vars."""
    if os.getenv("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.getenv("OPENAI_API_KEY"):
        return "openai"
    if os.getenv("GROQ_API_KEY"):
        return "groq"
    # Default to Anthropic (will warn if key missing)
    return "anthropic"


def _resolve_openai_compat_key(provider: str) -> str | None:
    """Resolve API key for OpenAI-compatible providers."""
    key_map = {
        "openai": "OPENAI_API_KEY",
        "groq": "GROQ_API_KEY",
        "together": "TOGETHER_API_KEY",
        "ollama": None,      # no key needed
        "lm_studio": None,   # no key needed
    }
    env_var = key_map.get(provider, "OPENAI_API_KEY")
    return os.getenv(env_var) if env_var else "local"
