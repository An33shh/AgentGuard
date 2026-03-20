"""Tests for Phase 7 — Provenance Tags (MITRE ATLAS AML.T0054)."""

from __future__ import annotations

import pytest

from agentguard.core.models import (
    Action,
    ActionType,
    Decision,
    ProvenanceSourceType,
    ProvenanceTag,
)
from agentguard.interceptor.interceptor import Interceptor
from agentguard.policy.engine import PolicyEngine
from agentguard.policy.schema import PolicyConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_external_tag(label: str = "GitHub issue body") -> ProvenanceTag:
    return ProvenanceTag(
        source_type=ProvenanceSourceType.EXTERNAL_DATA,
        label=label,
        value="snippet...",
    )


def make_tool_output_tag() -> ProvenanceTag:
    return ProvenanceTag(
        source_type=ProvenanceSourceType.TOOL_OUTPUT,
        label="web_search result",
    )


def make_system_tag() -> ProvenanceTag:
    return ProvenanceTag(
        source_type=ProvenanceSourceType.SYSTEM,
        label="openai_hooks",
    )


def deny_engine(*source_patterns: str) -> PolicyEngine:
    config = PolicyConfig(
        name="provenance-test",
        risk_threshold=0.75,
        review_threshold=0.60,
        deny_provenance_sources=list(source_patterns),
    )
    return PolicyEngine(config=config)


# ---------------------------------------------------------------------------
# ProvenanceTag model
# ---------------------------------------------------------------------------

class TestProvenanceTagModel:
    def test_required_fields(self) -> None:
        tag = ProvenanceTag(source_type=ProvenanceSourceType.USER_INSTRUCTION, label="user prompt")
        assert tag.source_type == ProvenanceSourceType.USER_INSTRUCTION
        assert tag.label == "user prompt"
        assert tag.value == ""
        assert tag.inherited_from is None

    def test_optional_fields(self) -> None:
        tag = ProvenanceTag(
            source_type=ProvenanceSourceType.TOOL_OUTPUT,
            label="search result",
            value="snippet",
            inherited_from="event-abc-123",
        )
        assert tag.inherited_from == "event-abc-123"

    def test_all_source_types_have_string_values(self) -> None:
        expected = {
            "user_instruction", "tool_output", "external_data",
            "agent_generated", "system",
        }
        actual = {t.value for t in ProvenanceSourceType}
        assert actual == expected


# ---------------------------------------------------------------------------
# PolicyEngine.evaluate_provenance()
# ---------------------------------------------------------------------------

class TestPolicyEngineProvenance:
    def test_blocks_denied_source_type(self) -> None:
        engine = deny_engine("external_data")
        decision, violation = engine.evaluate_provenance([make_external_tag()])
        assert decision == Decision.BLOCK
        assert violation is not None
        assert violation.rule_name == "deny_provenance_sources"
        assert violation.rule_type == "provenance"

    def test_allows_non_denied_source(self) -> None:
        engine = deny_engine("external_data")
        decision, violation = engine.evaluate_provenance([make_system_tag()])
        assert decision == Decision.ALLOW
        assert violation is None

    def test_allows_when_no_deny_sources_configured(self) -> None:
        engine = PolicyEngine(config=PolicyConfig(
            name="test", risk_threshold=0.75, review_threshold=0.60
        ))
        decision, _ = engine.evaluate_provenance([make_external_tag()])
        assert decision == Decision.ALLOW

    def test_allows_empty_provenance_tags(self) -> None:
        engine = deny_engine("external_data")
        decision, violation = engine.evaluate_provenance([])
        assert decision == Decision.ALLOW
        assert violation is None

    def test_wildcard_pattern_blocks_matching_types(self) -> None:
        engine = deny_engine("*_data")   # matches "external_data"
        decision, violation = engine.evaluate_provenance([make_external_tag()])
        assert decision == Decision.BLOCK
        assert violation is not None

    def test_wildcard_does_not_block_non_matching(self) -> None:
        engine = deny_engine("*_data")   # does NOT match "tool_output"
        decision, _ = engine.evaluate_provenance([make_tool_output_tag()])
        assert decision == Decision.ALLOW

    def test_multiple_patterns_any_match_blocks(self) -> None:
        engine = deny_engine("tool_output", "external_data")
        decision, violation = engine.evaluate_provenance([make_tool_output_tag()])
        assert decision == Decision.BLOCK

    def test_detail_contains_label(self) -> None:
        engine = deny_engine("external_data")
        _, violation = engine.evaluate_provenance([make_external_tag("malicious issue body")])
        assert "malicious issue body" in violation.detail

    def test_system_source_never_blocked_by_default(self) -> None:
        """system provenance is for adapter metadata — never denied by default config."""
        engine = PolicyEngine(config=PolicyConfig.from_yaml("policies/default.yaml"))
        decision, _ = engine.evaluate_provenance([make_system_tag()])
        assert decision == Decision.ALLOW


# ---------------------------------------------------------------------------
# Interceptor integration
# ---------------------------------------------------------------------------

class TestInterceptorProvenance:
    @pytest.mark.asyncio
    async def test_denied_provenance_blocks(
        self, event_ledger, mock_analyzer
    ) -> None:
        engine = deny_engine("external_data")
        inter = Interceptor(
            analyzer=mock_analyzer,
            policy_engine=engine,
            event_ledger=event_ledger,
        )
        decision, event = await inter.intercept(
            raw_payload={"tool_name": "file.read", "parameters": {"path": "README.md"}},
            agent_goal="Summarize README",
            session_id="prov-test-1",
            provenance_tags=[make_external_tag("malicious GitHub issue")],
        )
        assert decision == Decision.BLOCK
        assert event.policy_violation is not None
        assert event.policy_violation.rule_name == "deny_provenance_sources"

    @pytest.mark.asyncio
    async def test_allowed_provenance_passes_through(
        self, event_ledger, mock_analyzer
    ) -> None:
        engine = deny_engine("external_data")
        inter = Interceptor(
            analyzer=mock_analyzer,
            policy_engine=engine,
            event_ledger=event_ledger,
        )
        decision, event = await inter.intercept(
            raw_payload={"tool_name": "file.read", "parameters": {"path": "README.md"}},
            agent_goal="Summarize README",
            session_id="prov-test-2",
            provenance_tags=[make_system_tag()],
        )
        assert decision == Decision.ALLOW

    @pytest.mark.asyncio
    async def test_no_provenance_tags_is_safe(
        self, interceptor: Interceptor
    ) -> None:
        """Callers that don't supply provenance_tags must not be blocked by default."""
        decision, _ = await interceptor.intercept(
            raw_payload={"tool_name": "file.read", "parameters": {"path": "README.md"}},
            agent_goal="Summarize README",
            session_id="prov-test-3",
        )
        assert decision == Decision.ALLOW

    @pytest.mark.asyncio
    async def test_provenance_tags_stored_on_event(
        self, interceptor: Interceptor
    ) -> None:
        tag = make_system_tag()
        _, event = await interceptor.intercept(
            raw_payload={"tool_name": "file.read", "parameters": {"path": "README.md"}},
            agent_goal="Summarize README",
            session_id="prov-test-4",
            provenance_tags=[tag],
        )
        assert len(event.provenance) == 1
        assert event.provenance[0].source_type == ProvenanceSourceType.SYSTEM

    @pytest.mark.asyncio
    async def test_provenance_block_logged_to_ledger(
        self, event_ledger, mock_analyzer
    ) -> None:
        engine = deny_engine("external_data")
        inter = Interceptor(
            analyzer=mock_analyzer,
            policy_engine=engine,
            event_ledger=event_ledger,
        )
        session = "prov-ledger-test"
        await inter.intercept(
            raw_payload={"tool_name": "file.read", "parameters": {"path": "README.md"}},
            agent_goal="Summarize README",
            session_id=session,
            provenance_tags=[make_external_tag()],
        )
        events = await event_ledger.list_events(session_id=session)
        assert len(events) == 1
        assert events[0].policy_violation.rule_name == "deny_provenance_sources"

    @pytest.mark.asyncio
    async def test_provenance_check_runs_before_llm(
        self, event_ledger, mock_analyzer
    ) -> None:
        """Provenance block must fire before the LLM is called (zero-latency)."""
        engine = deny_engine("external_data")
        inter = Interceptor(
            analyzer=mock_analyzer,
            policy_engine=engine,
            event_ledger=event_ledger,
        )
        decision, event = await inter.intercept(
            raw_payload={"tool_name": "file.read", "parameters": {"path": "README.md"}},
            agent_goal="Summarize README",
            session_id="prov-precheck",
            provenance_tags=[make_external_tag()],
        )
        assert decision == Decision.BLOCK
        # policy_engine analyzer model means the LLM was never called
        assert event.assessment.analyzer_model == "policy_engine"
