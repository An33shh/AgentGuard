"""Cross-taxonomy mappings: attack_pattern / rule_type → MITRE ATLAS + OWASP Agentic AI."""

from __future__ import annotations

from dataclasses import dataclass, field

from agentguard.taxonomy.owasp import OwaspCategory


@dataclass(frozen=True)
class TaxonomyMapping:
    atlas_ids: list[str] = field(default_factory=list)
    owasp_categories: list[OwaspCategory] = field(default_factory=list)

    @property
    def primary_atlas_id(self) -> str | None:
        return self.atlas_ids[0] if self.atlas_ids else None

    @property
    def primary_owasp(self) -> OwaspCategory | None:
        return self.owasp_categories[0] if self.owasp_categories else None


_EMPTY = TaxonomyMapping()

# ---------------------------------------------------------------------------
# attack_pattern (from enrichment TRIAGE_TOOL) → taxonomy
# Keys match the attack_pattern enum values in agentguard/integrations/enrichment.py
# ---------------------------------------------------------------------------
ATTACK_PATTERN_TO_TAXONOMY: dict[str, TaxonomyMapping] = {
    "credential_exfiltration": TaxonomyMapping(
        atlas_ids=["AML.T0058", "AML.T0048"],
        owasp_categories=[OwaspCategory.AA03, OwaspCategory.AA06],
    ),
    "data_exfiltration": TaxonomyMapping(
        atlas_ids=["AML.T0057", "AML.T0048"],
        owasp_categories=[OwaspCategory.AA03],
    ),
    "prompt_injection": TaxonomyMapping(
        atlas_ids=["AML.T0051", "AML.T0054"],
        owasp_categories=[OwaspCategory.AA01],
    ),
    "goal_hijacking": TaxonomyMapping(
        atlas_ids=["AML.T0051", "AML.T0055"],
        owasp_categories=[OwaspCategory.AA01, OwaspCategory.AA04],
    ),
    "memory_poisoning": TaxonomyMapping(
        atlas_ids=["AML.T0061"],
        owasp_categories=[OwaspCategory.AA05],
    ),
    "privilege_escalation": TaxonomyMapping(
        atlas_ids=["AML.T0059"],
        owasp_categories=[OwaspCategory.AA06],
    ),
    "lateral_movement": TaxonomyMapping(
        atlas_ids=["AML.T0060"],
        owasp_categories=[OwaspCategory.AA08],
    ),
    "reconnaissance": TaxonomyMapping(
        atlas_ids=["AML.T0006", "AML.T0007"],
        owasp_categories=[OwaspCategory.AA04],
    ),
    "none": _EMPTY,
}

# ---------------------------------------------------------------------------
# rule_type (PolicyViolation.rule_type from engine.py) → taxonomy
# Keys are the exact rule_type strings used in agentguard/policy/engine.py
# ---------------------------------------------------------------------------
RULE_TYPE_TO_TAXONOMY: dict[str, TaxonomyMapping] = {
    "tool_blacklist": TaxonomyMapping(
        atlas_ids=["AML.T0051", "AML.T0043"],
        owasp_categories=[OwaspCategory.AA02],
    ),
    "tool_allowlist": TaxonomyMapping(
        atlas_ids=["AML.T0051"],
        owasp_categories=[OwaspCategory.AA02],
    ),
    "path_blacklist": TaxonomyMapping(
        atlas_ids=["AML.T0058", "AML.T0057"],
        owasp_categories=[OwaspCategory.AA03],
    ),
    "credential_pattern": TaxonomyMapping(
        atlas_ids=["AML.T0058"],
        owasp_categories=[OwaspCategory.AA03, OwaspCategory.AA06],
    ),
    "domain_blacklist": TaxonomyMapping(
        atlas_ids=["AML.T0048", "AML.T0057"],
        owasp_categories=[OwaspCategory.AA03],
    ),
    "tool_review": TaxonomyMapping(
        atlas_ids=["AML.T0051"],
        owasp_categories=[OwaspCategory.AA04],
    ),
    "risk_score": TaxonomyMapping(
        atlas_ids=[],
        owasp_categories=[OwaspCategory.AA04],
    ),
    "abac": TaxonomyMapping(
        atlas_ids=["AML.T0059"],
        owasp_categories=[OwaspCategory.AA06],
    ),
    "provenance": TaxonomyMapping(
        atlas_ids=["AML.T0054"],
        owasp_categories=[OwaspCategory.AA01],
    ),
    "session_max_actions": TaxonomyMapping(
        atlas_ids=["AML.T0049"],
        owasp_categories=[OwaspCategory.AA09],
    ),
    "session_max_blocked": TaxonomyMapping(
        atlas_ids=["AML.T0049"],
        owasp_categories=[OwaspCategory.AA09],
    ),
}


def lookup_by_attack_pattern(pattern: str) -> TaxonomyMapping:
    """Return taxonomy mapping for an enrichment attack_pattern string."""
    return ATTACK_PATTERN_TO_TAXONOMY.get(pattern, _EMPTY)


def lookup_by_rule_type(rule_type: str) -> TaxonomyMapping:
    """Return taxonomy mapping for a policy engine rule_type string."""
    return RULE_TYPE_TO_TAXONOMY.get(rule_type, _EMPTY)
