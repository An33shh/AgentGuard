"""Deterministic YAML-based policy rule evaluation.

Runs synchronously — zero latency, no LLM calls.
Evaluation order:
  1. session_limits   → BLOCK (before everything else)
  2. deny_tools       → BLOCK
  3. allow_tools      → BLOCK if tool not in allowlist (when list is non-empty)
  4. deny_path_patterns → BLOCK (glob with ** support)
  5. credential_access → BLOCK (belt-and-suspenders)
  6. deny_domains     → BLOCK (domain matching)
  7. review_tools     → REVIEW
  8. default          → ALLOW
"""

from __future__ import annotations

import fnmatch
import os
import re
from typing import Any

import structlog

from agentguard.core.models import Action, ActionType, Decision, PolicyViolation
from agentguard.interceptor.action_types import extract_file_path, extract_url_domain
from agentguard.policy.schema import PolicyConfig

logger = structlog.get_logger(__name__)


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


def _path_matches(path: str, pattern: str) -> bool:
    """
    Match a file path against a glob pattern.

    Supports:
    - ~ expansion to the real home directory
    - ** for any number of path segments
    - * for any characters within a single segment
    - ? for a single character
    """
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

        logger.info("policy_engine_loaded", policy_name=self._config.name)

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
        # Rule 1: deny_tools
        if self._config.deny_tools:
            for denied_tool in self._config.deny_tools:
                if fnmatch.fnmatch(action.tool_name.lower(), denied_tool.lower()):
                    violation = PolicyViolation(
                        rule_name="deny_tools",
                        rule_type="tool_blacklist",
                        detail=f"Tool '{action.tool_name}' is in deny list",
                        decision=Decision.BLOCK,
                    )
                    return Decision.BLOCK, violation

        # Rule 2: allow_tools — if configured, tool MUST be in the allowlist
        if self._config.allow_tools:
            in_allowlist = any(
                fnmatch.fnmatch(action.tool_name.lower(), p.lower())
                for p in self._config.allow_tools
            )
            if not in_allowlist:
                violation = PolicyViolation(
                    rule_name="allow_tools",
                    rule_type="tool_allowlist",
                    detail=f"Tool '{action.tool_name}' is not in the allow list",
                    decision=Decision.BLOCK,
                )
                return Decision.BLOCK, violation

        # Rule 3: deny_path_patterns (applies to file operations)
        if action.type in (ActionType.FILE_READ, ActionType.FILE_WRITE, ActionType.CREDENTIAL_ACCESS):
            path = extract_file_path(action.parameters)
            if path and self._config.deny_path_patterns:
                for pattern in self._config.deny_path_patterns:
                    if _path_matches(path, pattern):
                        violation = PolicyViolation(
                            rule_name="deny_path_patterns",
                            rule_type="path_blacklist",
                            detail=f"Path '{path}' matches deny pattern '{pattern}'",
                            decision=Decision.BLOCK,
                        )
                        return Decision.BLOCK, violation

        # Rule 4: Always block CREDENTIAL_ACCESS type (belt-and-suspenders)
        if action.type == ActionType.CREDENTIAL_ACCESS:
            path = extract_file_path(action.parameters)
            violation = PolicyViolation(
                rule_name="credential_access",
                rule_type="credential_pattern",
                detail=f"Credential path detected: {path or action.tool_name}",
                decision=Decision.BLOCK,
            )
            return Decision.BLOCK, violation

        # Rule 5: deny_domains
        if action.type == ActionType.HTTP_REQUEST and self._config.deny_domains:
            domain = extract_url_domain(action.parameters)
            if domain:
                for pattern in self._config.deny_domains:
                    if _domain_matches(domain, pattern):
                        violation = PolicyViolation(
                            rule_name="deny_domains",
                            rule_type="domain_blacklist",
                            detail=f"Domain '{domain}' matches deny pattern '{pattern}'",
                            decision=Decision.BLOCK,
                        )
                        return Decision.BLOCK, violation

        # Rule 6: review_tools
        if self._config.review_tools:
            for review_tool in self._config.review_tools:
                if fnmatch.fnmatch(action.tool_name.lower(), review_tool.lower()):
                    violation = PolicyViolation(
                        rule_name="review_tools",
                        rule_type="tool_review",
                        detail=f"Tool '{action.tool_name}' requires review",
                        decision=Decision.REVIEW,
                    )
                    return Decision.REVIEW, violation

        return Decision.ALLOW, None

    def evaluate_risk(self, risk_score: float) -> tuple[Decision, PolicyViolation | None]:
        """Evaluate risk score against policy thresholds."""
        if risk_score >= self._config.risk_threshold:
            violation = PolicyViolation(
                rule_name="risk_threshold",
                rule_type="risk_score",
                detail=f"Risk score {risk_score:.2f} >= threshold {self._config.risk_threshold}",
                decision=Decision.BLOCK,
            )
            return Decision.BLOCK, violation

        if risk_score >= self._config.review_threshold:
            violation = PolicyViolation(
                rule_name="review_threshold",
                rule_type="risk_score",
                detail=f"Risk score {risk_score:.2f} >= review threshold {self._config.review_threshold}",
                decision=Decision.REVIEW,
            )
            return Decision.REVIEW, violation

        return Decision.ALLOW, None

    def evaluate_session_limits(
        self,
        session_actions: int,
        session_blocked: int,
    ) -> tuple[Decision, PolicyViolation | None]:
        """Check whether a session has exceeded its configured limits."""
        limits = self._config.session_limits
        if limits.max_actions and session_actions >= limits.max_actions:
            violation = PolicyViolation(
                rule_name="session_limits",
                rule_type="session_max_actions",
                detail=f"Session has reached the max_actions limit ({limits.max_actions})",
                decision=Decision.BLOCK,
            )
            return Decision.BLOCK, violation
        if limits.max_blocked and session_blocked >= limits.max_blocked:
            violation = PolicyViolation(
                rule_name="session_limits",
                rule_type="session_max_blocked",
                detail=f"Session has reached the max_blocked limit ({limits.max_blocked})",
                decision=Decision.BLOCK,
            )
            return Decision.BLOCK, violation
        return Decision.ALLOW, None
