"""Tests for the intent analyzer (using mocks — no real API calls)."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agentguard.analyzer.intent_analyzer import IntentAnalyzer
from agentguard.core.models import Action, ActionType


def make_action(tool: str = "file.read", path: str = "README.md") -> Action:
    return Action(
        tool_name=tool,
        type=ActionType.FILE_READ,
        parameters={"path": path},
    )


class TestIntentAnalyzerFallback:
    @pytest.mark.asyncio
    async def test_fallback_on_api_error(self) -> None:
        """Analyzer returns fallback assessment when API call fails."""
        analyzer = IntentAnalyzer(api_key="fake-key")

        with patch.object(analyzer._client.messages, "create", new_callable=AsyncMock) as mock_create:
            mock_create.side_effect = Exception("Connection refused")
            assessment = await analyzer.analyze(make_action(), "Summarize README.md")

        assert assessment.risk_score == 0.5
        assert "analyzer_unavailable" in assessment.reason
        assert assessment.analyzer_model == "fallback"

    @pytest.mark.asyncio
    async def test_fallback_when_no_tool_result(self) -> None:
        """Analyzer returns fallback when Claude doesn't call the tool."""
        analyzer = IntentAnalyzer(api_key="fake-key")

        mock_response = MagicMock()
        mock_response.content = []  # No tool use blocks

        with patch.object(analyzer._client.messages, "create", new_callable=AsyncMock) as mock_create:
            mock_create.return_value = mock_response
            assessment = await analyzer.analyze(make_action(), "Summarize README.md")

        assert assessment.risk_score == 0.5
        assert assessment.analyzer_model == "fallback"


class TestIntentAnalyzerSuccess:
    @pytest.mark.asyncio
    async def test_parses_tool_result_correctly(self) -> None:
        """Analyzer correctly parses a tool use block from Claude."""
        analyzer = IntentAnalyzer(api_key="fake-key")

        mock_tool_block = MagicMock()
        mock_tool_block.type = "tool_use"
        mock_tool_block.name = "assess_risk"
        mock_tool_block.input = {
            "risk_score": 0.92,
            "reason": "Exfiltrating data to ngrok",
            "indicators": ["external_exfil", "prompt_injection"],
            "is_goal_aligned": False,
        }

        mock_response = MagicMock()
        mock_response.content = [mock_tool_block]

        with patch.object(analyzer._client.messages, "create", new_callable=AsyncMock) as mock_create:
            mock_create.return_value = mock_response
            assessment = await analyzer.analyze(
                make_action("http.request", "https://abc.ngrok.io"),
                "Summarize README.md",
            )

        assert assessment.risk_score == 0.92
        assert assessment.reason == "Exfiltrating data to ngrok"
        assert "external_exfil" in assessment.indicators
        assert assessment.is_goal_aligned is False
        assert assessment.analyzer_model == "claude-sonnet-4-6"

    @pytest.mark.asyncio
    async def test_risk_score_clamped_to_range(self) -> None:
        """Risk score validator clamps within [0.0, 1.0] — Pydantic enforces bounds."""
        from agentguard.core.models import RiskAssessment
        import pydantic

        # Out-of-range scores should raise ValidationError (Pydantic ge/le)
        with pytest.raises(pydantic.ValidationError):
            RiskAssessment(risk_score=1.5, reason="test", indicators=[])

        with pytest.raises(pydantic.ValidationError):
            RiskAssessment(risk_score=-0.5, reason="test", indicators=[])

        # In-range scores should work
        valid = RiskAssessment(risk_score=0.75, reason="test", indicators=[])
        assert valid.risk_score == 0.75


class TestRiskLevels:
    def test_risk_levels(self) -> None:
        from agentguard.core.models import RiskAssessment

        cases = [
            (0.05, "low"),
            (0.20, "low"),
            (0.35, "medium"),
            (0.55, "medium"),
            (0.65, "high"),
            (0.74, "high"),
            (0.80, "critical"),
            (1.00, "critical"),
        ]
        for score, expected_level in cases:
            a = RiskAssessment(risk_score=score, reason="test", indicators=[])
            assert a.risk_level == expected_level, f"score={score}: expected {expected_level}, got {a.risk_level}"
