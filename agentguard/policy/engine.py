"""Deterministic YAML-based policy rule evaluation.

Runs synchronously — zero latency, no LLM calls.

Full evaluation order (including interceptor-level checks):
  0. session_limits           → BLOCK (Interceptor, before any policy call)
  1. ABAC                     → BLOCK (Interceptor: evaluate_abac, deny_unregistered_tools)
  2. deny_tools               → BLOCK (evaluate)
  3. allow_tools              → BLOCK if tool not in allowlist (evaluate)
  3.5 deny_provenance_sources → BLOCK (evaluate_provenance, MITRE ATLAS AML.T0054)
  4. deny_path_patterns       → BLOCK glob with ** support (evaluate)
  5. credential_access        → BLOCK belt-and-suspenders (evaluate)
  6. deny_domains             → BLOCK domain matching (evaluate)
  7. review_tools             → REVIEW (evaluate)
  8. default                  → ALLOW (evaluate)
  9. risk_threshold           → BLOCK/REVIEW (evaluate_risk, after LLM analysis)
"""

from __future__ import annotations

import fnmatch
import os
import re
from typing import Any

import structlog

from agentguard.core.models import Action, ActionType, Decision, PolicyViolation, ProvenanceTag
from agentguard.interceptor.action_types import extract_file_path, extract_url_domain
from agentguard.policy.schema import PolicyConfig, RuleAnnotation
from agentguard.taxonomy import lookup_by_rule_type

logger = structlog.get_logger(__name__)


def _make_violation(
    rule_name: str,
    rule_type: str,
    detail: str,
    decision: Decision,
    rule_annotations: dict[str, RuleAnnotation] | None = None,
) -> PolicyViolation:
    """
    Construct a PolicyViolation auto-annotated with MITRE ATLAS and OWASP taxonomy.

    Auto-detects taxonomy from RULE_TYPE_TO_TAXONOMY; merges (union) any per-rule
    overrides from the policy YAML rule_annotations block.
    """
    mapping = lookup_by_rule_type(rule_type)
    atlas_ids = list(mapping.atlas_ids)
    owasp_cats = [c.value for c in mapping.owasp_categories]

    if rule_annotations and rule_name in rule_annotations:
        override = rule_annotations[rule_name]
        for aid in override.mitre_atlas_ids:
            if aid not in atlas_ids:
                atlas_ids.append(aid)
        for cat in override.owasp_categories:
            if cat not in owasp_cats:
                owasp_cats.append(cat)

    return PolicyViolation(
        rule_name=rule_name,
        rule_type=rule_type,
        detail=detail,
        decision=decision,
        mitre_atlas_ids=atlas_ids,
        owasp_categories=owasp_cats,
    )


def _domain_matches(domain: str, pattern: str) -> bool:
    """Match domain against pattern, supporting wildcards like *.ngrok.io."""
    if pattern.startswith("*."):
        suffix = pattern[1:]  # e.g. ".ngrok.io"
        return domain == pattern[2:] or domain.endswith(suffix)
    return domain == pattern or fnmatch.fnmatch(domain, pattern)


def _glob_to_regex(pattern: str) -> str:
    """Convert a glob pattern with ** and * support to a regex string."""
    parts: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern[i : i + 3] == "**/":
            parts.append("(?:.+/)?")  # zero or more path segments followed by /
            i += 3
        elif pattern[i : i + 2] == "**":
            parts.append(".*")
            i += 2
        elif pattern[i] == "*":
            parts.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            parts.append("[^/]")
            i += 1
        else:
            parts.append(re.escape(pattern[i]))
            i += 1
    return "".join(parts)


_MAX_PATH_LEN = 4096


def _path_matches(path: str, pattern: str) -> bool:
    """
    Match a file path against a glob pattern.

    Supports:
    - ~ expansion to the real home directory
    - ** for any number of path segments
    - * for any characters within a single segment
    - ? for a single character
    """
    # Guard against ReDoS: adversarially long paths can cause quadratic
    # backtracking in the ** glob regex. Real file paths are never this long.
    if len(path) > _MAX_PATH_LEN:
        return False
    # Normalise separators and expand ~ in both sides
    expanded_path = os.path.expanduser(path).replace("\\", "/").rstrip("/")
    expanded_pattern = os.path.expanduser(pattern).replace("\\", "/").rstrip("/")

    regex = _glob_to_regex(expanded_pattern)
    return bool(re.fullmatch(regex, expanded_path))


class PolicyEngine:
    """
    Synchronous, deterministic policy rule evaluator.

    Hot-reload supported via engine.reload(path).
    """

    def __init__(self, config: PolicyConfig | None = None, path: str | None = None) -> None:
        if path:
            self._config = PolicyConfig.from_yaml(path)
            self._path = path
        elif config:
            self._config = config
            self._path = None
        else:
            self._config = PolicyConfig()
            self._path = None

        self._compile_patterns()
        logger.info("policy_engine_loaded", policy_name=self._config.name)

    def _compile_patterns(self) -> None:
        """Pre-compile all glob and domain patterns from the current config."""
        self._path_patterns: list[tuple[re.Pattern[str], str]] = [
            (re.compile(_glob_to_regex(os.path.expanduser(p).replace("\\", "/").rstrip("/"))), p)
            for p in (self._config.deny_path_patterns or [])
        ]
        # Domain patterns: *.xxx → fast suffix check; others → pre-compiled fnmatch regex
        self._domain_patterns: list[tuple[str, re.Pattern[str] | None]] = []
        for p in (self._config.deny_domains or []):
            if p.startswith("*."):
                self._domain_patterns.append((p[1:], None))  # suffix string, no regex needed
            else:
                self._domain_patterns.append(("", re.compile(fnmatch.translate(p))))
        self._deny_tool_patterns: list[re.Pattern[str]] = [
            re.compile(fnmatch.translate(t.lower())) for t in (self._config.deny_tools or [])
        ]
        self._allow_tool_patterns: list[re.Pattern[str]] = [
            re.compile(fnmatch.translate(t.lower())) for t in (self._config.allow_tools or [])
        ]
        self._review_tool_patterns: list[re.Pattern[str]] = [
            re.compile(fnmatch.translate(t.lower())) for t in (self._config.review_tools or [])
        ]
        self._unregistered_tool_patterns: list[re.Pattern[str]] = [
            re.compile(fnmatch.translate(t.lower())) for t in (self._config.deny_unregistered_tools or [])
        ]
        self._provenance_patterns: list[re.Pattern[str]] = [
            re.compile(fnmatch.translate(p)) for p in (self._config.deny_provenance_sources or [])
        ]

    @classmethod
    def from_yaml(cls, path: str) -> "PolicyEngine":
        return cls(path=path)

    def reload(self, path: str | None = None) -> None:
        """Hot-reload policy from disk."""
        reload_path = path or self._path
        if not reload_path:
            raise ValueError("No policy path to reload from")
        self._config = PolicyConfig.from_yaml(reload_path)
        self._path = reload_path
        self._compile_patterns()
        logger.info("policy_reloaded", policy_name=self._config.name)

    @property
    def config(self) -> PolicyConfig:
        return self._config

    def evaluate(self, action: Action) -> tuple[Decision, PolicyViolation | None]:
        """
        Evaluate an action against deterministic policy rules.

        Returns (Decision, PolicyViolation | None).
        Does NOT evaluate risk_threshold — call evaluate_risk() separately.
        """
        ra = self._config.rule_annotations or None

        tool_lower = action.tool_name.lower()

        # Rule 1: deny_tools
        for pat in self._deny_tool_patterns:
            if pat.match(tool_lower):
                return Decision.BLOCK, _make_violation(
                    "deny_tools", "tool_blacklist",
                    f"Tool '{action.tool_name}' is in deny list",
                    Decision.BLOCK, ra,
                )

        # Rule 2: allow_tools — if configured, tool MUST be in the allowlist
        if self._allow_tool_patterns:
            if not any(p.match(tool_lower) for p in self._allow_tool_patterns):
                return Decision.BLOCK, _make_violation(
                    "allow_tools", "tool_allowlist",
                    f"Tool '{action.tool_name}' is not in the allow list",
                    Decision.BLOCK, ra,
                )

        # Rule 3: deny_path_patterns (applies to file operations)
        if action.type in (ActionType.FILE_READ, ActionType.FILE_WRITE, ActionType.CREDENTIAL_ACCESS):
            path = extract_file_path(action.parameters)
            if path and self._path_patterns:
                if len(path) <= _MAX_PATH_LEN:
                    expanded = os.path.expanduser(path).replace("\\", "/").rstrip("/")
                    for compiled, raw_pattern in self._path_patterns:
                        if compiled.fullmatch(expanded):
                            return Decision.BLOCK, _make_violation(
                                "deny_path_patterns", "path_blacklist",
                                f"Path '{path}' matches deny pattern '{raw_pattern}'",
                                Decision.BLOCK, ra,
                            )

        # Rule 4: Always block CREDENTIAL_ACCESS type (belt-and-suspenders)
        if action.type == ActionType.CREDENTIAL_ACCESS:
            path = extract_file_path(action.parameters)
            return Decision.BLOCK, _make_violation(
                "credential_access", "credential_pattern",
                f"Credential path detected: {path or action.tool_name}",
                Decision.BLOCK, ra,
            )

        # Rule 5: deny_domains
        if action.type == ActionType.HTTP_REQUEST and self._domain_patterns:
            domain = extract_url_domain(action.parameters)
            if domain:
                for suffix, pat in self._domain_patterns:
                    if suffix:  # *.xxx style: fast suffix check
                        if domain == suffix[1:] or domain.endswith(suffix):
                            return Decision.BLOCK, _make_violation(
                                "deny_domains", "domain_blacklist",
                                f"Domain '{domain}' matches deny pattern '*.{suffix[1:]}'",
                                Decision.BLOCK, ra,
                            )
                    elif pat and pat.match(domain):  # fnmatch pattern (exact or wildcard)
                        return Decision.BLOCK, _make_violation(
                            "deny_domains", "domain_blacklist",
                            f"Domain '{domain}' matches deny pattern",
                            Decision.BLOCK, ra,
                        )

        # Rule 6: review_tools
        for pat in self._review_tool_patterns:
            if pat.match(tool_lower):
                return Decision.REVIEW, _make_violation(
                    "review_tools", "tool_review",
                    f"Tool '{action.tool_name}' requires review",
                    Decision.REVIEW, ra,
                )

        return Decision.ALLOW, None

    def evaluate_abac(
        self,
        action: Action,
        is_registered: bool,
    ) -> tuple[Decision, PolicyViolation | None]:
        """
        Attribute-Based Access Control evaluation.

        deny_unregistered_tools: tools blocked for auto-detected (unregistered) agents.
        """
        if not is_registered and self._unregistered_tool_patterns:
            ra = self._config.rule_annotations or None
            tool_lower = action.tool_name.lower()
            for pat in self._unregistered_tool_patterns:
                if pat.match(tool_lower):
                    return Decision.BLOCK, _make_violation(
                        "deny_unregistered_tools", "abac",
                        f"Tool '{action.tool_name}' requires a registered agent identity. "
                        "Provide an explicit agent_id to use this tool.",
                        Decision.BLOCK, ra,
                    )
        return Decision.ALLOW, None

    def evaluate_provenance(
        self,
        provenance_tags: list[ProvenanceTag],
    ) -> tuple[Decision, PolicyViolation | None]:
        """
        Evaluate provenance tags against the deny_provenance_sources policy.

        Blocks actions whose input data originates from a denied source type.
        Addresses MITRE ATLAS AML.T0054 (Prompt Injection via Tool Outputs).
        """
        if not self._provenance_patterns or not provenance_tags:
            return Decision.ALLOW, None
        ra = self._config.rule_annotations or None
        for tag in provenance_tags:
            for pat in self._provenance_patterns:
                if pat.match(tag.source_type.value):
                    return Decision.BLOCK, _make_violation(
                        "deny_provenance_sources", "provenance",
                        f"Action triggered by denied source '{tag.source_type.value}': {tag.label}",
                        Decision.BLOCK, ra,
                    )
        return Decision.ALLOW, None

    def effective_thresholds(self, session_blocked: int) -> tuple[float, float]:
        """
        Return (risk_threshold, review_threshold) for this session.

        If demotion is enabled and the session has accumulated enough blocks,
        tighter thresholds are returned automatically — no restart needed.
        """
        cfg = self._config.demotion
        if cfg.enabled and session_blocked >= cfg.trigger_blocked_count:
            return cfg.demoted_risk_threshold, cfg.demoted_review_threshold
        return self._config.risk_threshold, self._config.review_threshold

    def evaluate_risk(
        self,
        risk_score: float,
        risk_threshold: float | None = None,
        review_threshold: float | None = None,
    ) -> tuple[Decision, PolicyViolation | None]:
        """Evaluate risk score against policy thresholds (supports demotion overrides)."""
        threshold = risk_threshold if risk_threshold is not None else self._config.risk_threshold
        r_threshold = review_threshold if review_threshold is not None else self._config.review_threshold
        # Only validate cross-threshold ordering when both are explicitly overridden —
        # if only one is overridden the caller is responsible for providing a consistent pair
        # (effective_thresholds() always returns a validated pair).
        if risk_threshold is not None and review_threshold is not None and r_threshold >= threshold:
            raise ValueError(
                f"review_threshold ({r_threshold}) must be less than risk_threshold ({threshold})"
            )

        ra = self._config.rule_annotations or None

        if risk_score >= threshold:
            return Decision.BLOCK, _make_violation(
                "risk_threshold", "risk_score",
                f"Risk score {risk_score:.2f} >= threshold {threshold:.2f}",
                Decision.BLOCK, ra,
            )

        if risk_score >= r_threshold:
            return Decision.REVIEW, _make_violation(
                "review_threshold", "risk_score",
                f"Risk score {risk_score:.2f} >= review threshold {r_threshold:.2f}",
                Decision.REVIEW, ra,
            )

        return Decision.ALLOW, None

    def evaluate_session_limits(
        self,
        session_actions: int,
        session_blocked: int,
    ) -> tuple[Decision, PolicyViolation | None]:
        """Check whether a session has exceeded its configured limits."""
        limits = self._config.session_limits
        ra = self._config.rule_annotations or None
        if limits.max_actions and session_actions >= limits.max_actions:
            return Decision.BLOCK, _make_violation(
                "session_limits", "session_max_actions",
                f"Session has reached the max_actions limit ({limits.max_actions})",
                Decision.BLOCK, ra,
            )
        if limits.max_blocked and session_blocked >= limits.max_blocked:
            return Decision.BLOCK, _make_violation(
                "session_limits", "session_max_blocked",
                f"Session has reached the max_blocked limit ({limits.max_blocked})",
                Decision.BLOCK, ra,
            )
        return Decision.ALLOW, None
