"""Tests for OpenAICompatBackend (using mocks — no real API calls).

AsyncOpenAI is imported lazily inside __init__, so we patch at the openai
module level rather than at the backends.openai_compat module level.
"""

from __future__ import annotations

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agentguard.analyzer.backends.openai_compat import OpenAICompatBackend
from agentguard.analyzer.intent_analyzer import IntentAnalyzer
from agentguard.core.models import Action, ActionType


def make_action(tool: str = "file.read", path: str = "README.md") -> Action:
    return Action(
        tool_name=tool,
        type=ActionType.FILE_READ,
        parameters={"path": path},
    )


def make_tool_call_response(
    risk_score: float, reason: str, indicators: list, is_goal_aligned: bool
) -> MagicMock:
    """Build a mock OpenAI chat completion response with an assess_risk tool call."""
    tc = MagicMock()
    tc.function.name = "assess_risk"
    tc.function.arguments = json.dumps({
        "risk_score": risk_score,
        "reason": reason,
        "indicators": indicators,
        "is_goal_aligned": is_goal_aligned,
    })
    message = MagicMock()
    message.tool_calls = [tc]
    choice = MagicMock()
    choice.message = message
    response = MagicMock()
    response.choices = [choice]
    return response


def _make_backend(model: str = "gpt-4o", provider_name: str = "openai") -> tuple[OpenAICompatBackend, MagicMock]:
    """Create an OpenAICompatBackend with a mocked AsyncOpenAI client."""
    mock_client = MagicMock()
    with patch("openai.AsyncOpenAI", return_value=mock_client):
        backend = OpenAICompatBackend(api_key="fake", model=model, provider_name=provider_name)
    return backend, mock_client


class TestOpenAICompatBackendProperties:
    def test_default_provider_and_model(self) -> None:
        backend, _ = _make_backend()
        assert backend.provider == "openai"
        assert backend.model == "gpt-4o"

    def test_custom_provider_name_and_model(self) -> None:
        backend, _ = _make_backend(model="llama3.1", provider_name="ollama")
        assert backend.provider == "ollama"
        assert backend.model == "llama3.1"


class TestOpenAICompatBackendAssess:
    @pytest.mark.asyncio
    async def test_parses_tool_call_correctly(self) -> None:
        """Backend correctly parses an assess_risk tool call response."""
        backend, mock_client = _make_backend()
        mock_client.chat.completions.create = AsyncMock(
            return_value=make_tool_call_response(0.88, "Exfiltrating to requestbin", ["data_exfiltration"], False)
        )
        assessment = await backend.assess(
            make_action("http.post", "https://xyz.requestbin.com"),
            "Summarize README.md",
        )
        assert assessment.risk_score == 0.88
        assert assessment.reason == "Exfiltrating to requestbin"
        assert "data_exfiltration" in assessment.indicators
        assert assessment.is_goal_aligned is False
        assert assessment.analyzer_model == "openai/gpt-4o"

    @pytest.mark.asyncio
    async def test_raises_when_no_tool_call(self) -> None:
        """Backend raises ValueError when response contains no assess_risk call."""
        backend, mock_client = _make_backend()
        message = MagicMock()
        message.tool_calls = []
        choice = MagicMock()
        choice.message = message
        response = MagicMock()
        response.choices = [choice]
        mock_client.chat.completions.create = AsyncMock(return_value=response)

        with pytest.raises(ValueError, match="no assess_risk tool call"):
            await backend.assess(make_action(), "Summarize README.md")

    @pytest.mark.asyncio
    async def test_analyzer_model_includes_provider_prefix(self) -> None:
        """analyzer_model includes provider prefix for traceability."""
        backend, mock_client = _make_backend(model="llama3.1", provider_name="ollama")
        mock_client.chat.completions.create = AsyncMock(
            return_value=make_tool_call_response(0.05, "safe action", [], True)
        )
        assessment = await backend.assess(make_action(), "Summarize README.md")
        assert assessment.analyzer_model == "ollama/llama3.1"

    @pytest.mark.asyncio
    async def test_safe_action_low_risk(self) -> None:
        """Backend correctly maps a low-risk response."""
        backend, mock_client = _make_backend()
        mock_client.chat.completions.create = AsyncMock(
            return_value=make_tool_call_response(0.05, "Reading docs file", [], True)
        )
        assessment = await backend.assess(make_action("file.read", "README.md"), "Summarize README.md")
        assert assessment.risk_score == 0.05
        assert assessment.is_goal_aligned is True


class TestIntentAnalyzerWithOpenAIBackend:
    @pytest.mark.asyncio
    async def test_fallback_on_api_error(self) -> None:
        """IntentAnalyzer falls back gracefully when OpenAI backend errors."""
        backend, mock_client = _make_backend()
        mock_client.chat.completions.create = AsyncMock(side_effect=Exception("Connection refused"))
        analyzer = IntentAnalyzer(backend=backend)
        assessment = await analyzer.analyze(make_action(), "Summarize README.md")
        assert assessment.risk_score == 0.5
        assert "analyzer_unavailable" in assessment.reason
        assert assessment.analyzer_model == "fallback"

    @pytest.mark.asyncio
    async def test_fail_closed_on_credential_access_error(self) -> None:
        """Fail-closed: CREDENTIAL_ACCESS defaults to score=1.0 when OpenAI backend errors."""
        cred_action = Action(
            tool_name="file.read",
            type=ActionType.CREDENTIAL_ACCESS,
            parameters={"path": "~/.aws/credentials"},
        )
        backend, mock_client = _make_backend()
        mock_client.chat.completions.create = AsyncMock(side_effect=Exception("timeout"))
        analyzer = IntentAnalyzer(backend=backend)
        assessment = await analyzer.analyze(cred_action, "Summarize README.md")
        assert assessment.risk_score == 1.0
        assert assessment.analyzer_model == "fallback"
