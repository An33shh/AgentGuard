"""Shared test fixtures."""

from __future__ import annotations

import pytest
import pytest_asyncio

from agentguard.analyzer.intent_analyzer import IntentAnalyzer
from agentguard.core.models import Action, ActionType, Decision, RiskAssessment
from agentguard.interceptor.interceptor import Interceptor
from agentguard.ledger.event_ledger import InMemoryEventLedger
from agentguard.policy.engine import PolicyEngine
from agentguard.policy.schema import PolicyConfig


@pytest.fixture
def default_policy_config() -> PolicyConfig:
    return PolicyConfig(
        name="test",
        risk_threshold=0.75,
        review_threshold=0.60,
        deny_tools=["shell.execute", "bash.run", "bash", "shell"],
        deny_path_patterns=[
            "~/.ssh/**",
            "~/.ssh/id_rsa",
            "~/.aws/credentials",
            "~/.env",
            "**/.env",
            "**/*.pem",
            "**/*.key",
        ],
        deny_domains=[
            "*.ngrok.io",
            "*.requestbin.com",
            "webhook.site",
        ],
        review_tools=["email.send", "file.write", "git.push"],
        session_limits={"max_actions": 100, "max_blocked": 10},
    )


@pytest.fixture
def policy_engine(default_policy_config: PolicyConfig) -> PolicyEngine:
    return PolicyEngine(config=default_policy_config)


@pytest.fixture
def event_ledger() -> InMemoryEventLedger:
    return InMemoryEventLedger()


@pytest.fixture
def mock_analyzer() -> "MockAnalyzer":
    return MockAnalyzer()


@pytest.fixture
def interceptor(mock_analyzer: "MockAnalyzer", policy_engine: PolicyEngine, event_ledger: InMemoryEventLedger) -> Interceptor:
    return Interceptor(
        analyzer=mock_analyzer,
        policy_engine=policy_engine,
        event_ledger=event_ledger,
    )


class MockAnalyzer:
    """Mock analyzer that returns pre-defined risk scores based on tool/path."""

    RISK_MAP: dict[str, float] = {
        # Attack scenarios — keys are substrings matched against params + tool_name
        "ngrok": 0.92,
        "requestbin": 0.88,
        "id_rsa": 0.45,
        "override": 0.81,   # catches memory-poisoning payloads containing "OVERRIDE"
        "aws/credentials": 0.95,
        # Legitimate
        "readme.md": 0.05,
    }

    def __init__(self, default_score: float = 0.5) -> None:
        self.default_score = default_score
        self._custom_scores: dict[str, float] = {}

    def set_score(self, key: str, score: float) -> None:
        """Pre-configure a risk score for a specific key."""
        self._custom_scores[key] = score

    async def analyze(self, action: Action, agent_goal: str) -> RiskAssessment:
        """Return risk score based on action content."""
        params_str = str(action.parameters).lower()
        tool_name = action.tool_name.lower()

        # Check custom scores first
        for key, score in self._custom_scores.items():
            if key in params_str or key in tool_name:
                return self._make_assessment(score, f"mock_{key}")

        # Check default risk map
        for key, score in self.RISK_MAP.items():
            if key in params_str:
                return self._make_assessment(score, f"mock_{key}")

        return self._make_assessment(self.default_score, "mock_default")

    def _make_assessment(self, score: float, reason: str) -> RiskAssessment:
        return RiskAssessment(
            risk_score=score,
            reason=reason,
            indicators=["mock_indicator"] if score > 0.5 else [],
            is_goal_aligned=score < 0.5,
            analyzer_model="mock",
            latency_ms=1.0,
        )
