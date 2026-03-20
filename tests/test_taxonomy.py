"""Tests for the MITRE ATLAS + OWASP Agentic AI taxonomy module."""

from __future__ import annotations

import pytest

from agentguard.taxonomy import (
    ATLAS_TECHNIQUES,
    OWASP_ENTRIES,
    OwaspCategory,
    lookup_by_attack_pattern,
    lookup_by_rule_type,
)
from agentguard.taxonomy.mappings import ATTACK_PATTERN_TO_TAXONOMY, TaxonomyMapping


class TestAtlasTaxonomy:
    def test_all_techniques_have_required_fields(self):
        for tid, tech in ATLAS_TECHNIQUES.items():
            assert tech.technique_id, f"{tid} missing technique_id"
            assert tech.name, f"{tid} missing name"
            assert tech.tactic, f"{tid} missing tactic"
            assert tech.description, f"{tid} missing description"

    def test_fifteen_techniques_present(self):
        assert len(ATLAS_TECHNIQUES) == 15

    def test_key_techniques_present(self):
        for expected in ["AML.T0051", "AML.T0054", "AML.T0058", "AML.T0061"]:
            assert expected in ATLAS_TECHNIQUES

    def test_url_property(self):
        tech = ATLAS_TECHNIQUES["AML.T0054"]
        assert tech.url == "https://atlas.mitre.org/techniques/AML.T0054"


class TestOwaspTaxonomy:
    def test_all_ten_entries_present(self):
        assert len(OWASP_ENTRIES) == 10

    def test_all_categories_aa01_to_aa10(self):
        for i in range(1, 11):
            cat = OwaspCategory(f"AA{i:02d}")
            assert cat in OWASP_ENTRIES

    def test_entries_have_required_fields(self):
        for cat, entry in OWASP_ENTRIES.items():
            assert entry.name, f"{cat} missing name"
            assert entry.description, f"{cat} missing description"


class TestMappings:
    def test_credential_exfiltration_maps_to_atlas(self):
        m = lookup_by_attack_pattern("credential_exfiltration")
        assert "AML.T0058" in m.atlas_ids
        assert "AML.T0048" in m.atlas_ids

    def test_credential_exfiltration_maps_to_owasp(self):
        m = lookup_by_attack_pattern("credential_exfiltration")
        cats = [c.value for c in m.owasp_categories]
        assert "AA03" in cats
        assert "AA06" in cats

    def test_prompt_injection_maps_correctly(self):
        m = lookup_by_attack_pattern("prompt_injection")
        assert "AML.T0051" in m.atlas_ids
        assert "AML.T0054" in m.atlas_ids
        cats = [c.value for c in m.owasp_categories]
        assert "AA01" in cats

    def test_goal_hijacking_maps_correctly(self):
        m = lookup_by_attack_pattern("goal_hijacking")
        cats = [c.value for c in m.owasp_categories]
        assert "AA01" in cats
        assert "AA04" in cats

    def test_memory_poisoning_maps_correctly(self):
        m = lookup_by_attack_pattern("memory_poisoning")
        assert "AML.T0061" in m.atlas_ids
        cats = [c.value for c in m.owasp_categories]
        assert "AA05" in cats

    def test_unknown_pattern_returns_empty(self):
        m = lookup_by_attack_pattern("nonexistent_pattern")
        assert m.atlas_ids == []
        assert m.owasp_categories == []
        assert m.primary_atlas_id is None
        assert m.primary_owasp is None

    def test_none_pattern_returns_empty(self):
        m = lookup_by_attack_pattern("none")
        assert m.atlas_ids == []

    def test_all_enrichment_attack_patterns_covered(self):
        # These are the exact values used in enrichment.py TRIAGE_TOOL
        enrichment_patterns = [
            "credential_exfiltration",
            "data_exfiltration",
            "prompt_injection",
            "goal_hijacking",
            "memory_poisoning",
            "privilege_escalation",
            "lateral_movement",
            "reconnaissance",
            "none",
        ]
        for pattern in enrichment_patterns:
            assert pattern in ATTACK_PATTERN_TO_TAXONOMY, f"Missing mapping for: {pattern}"

    def test_provenance_rule_type_maps_correctly(self):
        m = lookup_by_rule_type("provenance")
        assert "AML.T0054" in m.atlas_ids
        cats = [c.value for c in m.owasp_categories]
        assert "AA01" in cats

    def test_credential_pattern_rule_type_maps_correctly(self):
        m = lookup_by_rule_type("credential_pattern")
        assert "AML.T0058" in m.atlas_ids
        cats = [c.value for c in m.owasp_categories]
        assert "AA03" in cats

    def test_domain_blacklist_rule_type_maps_correctly(self):
        m = lookup_by_rule_type("domain_blacklist")
        assert "AML.T0048" in m.atlas_ids

    def test_unknown_rule_type_returns_empty(self):
        m = lookup_by_rule_type("unknown_rule_type")
        assert m.atlas_ids == []
        assert m.owasp_categories == []


class TestPolicyViolationTaxonomy:
    """Verify that engine auto-annotates PolicyViolation with taxonomy IDs."""

    def test_deny_tools_violation_has_atlas_ids(self, policy_engine):
        from agentguard.core.models import Action, ActionType
        action = Action(tool_name="shell.execute", type=ActionType.SHELL_COMMAND, parameters={})
        decision, violation = policy_engine.evaluate(action)
        assert violation is not None
        assert "AML.T0051" in violation.mitre_atlas_ids
        assert "AA02" in violation.owasp_categories

    def test_credential_pattern_violation_has_atlas_ids(self, policy_engine):
        from agentguard.core.models import Action, ActionType
        action = Action(tool_name="file.read", type=ActionType.CREDENTIAL_ACCESS,
                        parameters={"path": "~/.aws/credentials"})
        decision, violation = policy_engine.evaluate(action)
        assert violation is not None
        assert "AML.T0058" in violation.mitre_atlas_ids
        assert "AA03" in violation.owasp_categories

    def test_provenance_violation_has_atlas_ids(self, policy_engine):
        from agentguard.core.models import ProvenanceTag, ProvenanceSourceType
        from agentguard.policy.schema import PolicyConfig
        from agentguard.policy.engine import PolicyEngine
        config = PolicyConfig(
            risk_threshold=0.75,
            review_threshold=0.60,
            deny_provenance_sources=["external_data"],
        )
        engine = PolicyEngine(config=config)
        tags = [ProvenanceTag(source_type=ProvenanceSourceType.EXTERNAL_DATA, label="test")]
        decision, violation = engine.evaluate_provenance(tags)
        assert violation is not None
        assert "AML.T0054" in violation.mitre_atlas_ids
        assert "AA01" in violation.owasp_categories

    def test_rule_annotations_merged_into_violation(self):
        from agentguard.core.models import Action, ActionType
        from agentguard.policy.engine import PolicyEngine
        from agentguard.policy.schema import PolicyConfig, RuleAnnotation
        config = PolicyConfig(
            risk_threshold=0.75,
            review_threshold=0.60,
            deny_tools=["shell.execute"],
            rule_annotations={
                "deny_tools": RuleAnnotation(
                    mitre_atlas_ids=["AML.T0062"],
                    owasp_categories=["AA07"],
                    notes="Custom annotation",
                )
            },
        )
        engine = PolicyEngine(config=config)
        action = Action(tool_name="shell.execute", type=ActionType.SHELL_COMMAND, parameters={})
        decision, violation = engine.evaluate(action)
        assert violation is not None
        # Auto-detected IDs still present
        assert "AML.T0051" in violation.mitre_atlas_ids
        # Custom annotation merged in
        assert "AML.T0062" in violation.mitre_atlas_ids
        assert "AA07" in violation.owasp_categories
