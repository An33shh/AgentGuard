"""Deterministic YAML-based policy rule evaluation.

Runs synchronously — zero latency, no LLM calls.

Full evaluation order (including interceptor-level checks):
  0. session_limits           → BLOCK (Interceptor, before any policy call)
  1. ABAC                     → BLOCK (Interceptor: evaluate_abac, deny_unregistered_tools)
  2. deny_tools               → BLOCK (evaluate)
  2.5 shell_command_policy    → BLOCK destructive shell content, SHELL_COMMAND only (evaluate)
  3. allow_tools              → BLOCK if tool not in allowlist (evaluate)
  3.5 deny_provenance_sources → BLOCK (evaluate_provenance, MITRE ATLAS AML.T0054)
  4. deny_path_patterns       → BLOCK glob with ** support (evaluate)
  5. credential_access        → BLOCK belt-and-suspenders (evaluate)
  6. deny_domains             → BLOCK domain matching (evaluate)
  7. review_tools             → REVIEW (evaluate)
  8. default                  → ALLOW (evaluate)
  9. risk_threshold           → BLOCK/REVIEW (evaluate_risk, after LLM analysis)

Rule 2.5 (shell_command_policy) is deliberately content-aware rather than a
blanket tool-name ban like deny_tools: it inspects the actual command string
for objectively dangerous patterns (rm -rf, fork bombs, piping a remote
fetch into a shell, etc. — see agentguard.analyzer.patterns's
DESTRUCTIVE_SHELL category) instead of denying the "bash" tool outright.
Anything that doesn't match still falls through to allow_tools and,
eventually, LLM-based risk scoring — this is a fast lane for the obvious
cases, not a replacement for semantic judgment on ambiguous ones. An
operator who wants a categorical "no agent ever runs Bash" ban can still
express that via deny_tools (unchanged, see policies/strict.yaml).

Rules 2.5, 4, 5, and 6 (shell_command_policy, deny_path_patterns,
credential_access, deny_domains) scan every string-valued parameter
recursively (agentguard.interceptor.action_types.iter_all_string_values),
NOT gated on the action's inferred ActionType. A pentest found the
type-gated version of every one of these trivially bypassed by any
tool/parameter naming outside infer_action_type()'s hardcoded lexicon
(action_types.py's _SHELL_COMMAND_KEYS / path_keys / url_keys) — the action
falls back to ActionType.TOOL_CALL, which none of the type-gated rules
scrutinize at all. Classification is an inherently-defeatable heuristic
(useful for descriptive/audit purposes and Rule 4's tool-name-driven
credential_access trigger, which is additionally preserved); the actual
BLOCK/ALLOW decision must not depend on it succeeding.
"""

from __future__ import annotations

import fnmatch
import os
import posixpath
import re

import structlog

from agentguard.analyzer.patterns import DetectionCategory, patterns_for
from agentguard.core.models import Action, ActionType, Decision, PolicyViolation, ProvenanceTag
from agentguard.interceptor.action_types import (
    extract_file_path,
    is_credential_path,
    iter_all_domains,
    iter_all_string_values,
)
from agentguard.policy._native import RUST_AVAILABLE, build_native_matcher
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

# Minimum agentguard.analyzer.patterns.Pattern.confidence for a built-in
# DESTRUCTIVE_SHELL pattern to participate in shell_command_policy's
# unconditional, every-parameter, hard-BLOCK sweep — see
# PolicyEngine._build_shell_deny_patterns's docstring. 0.85 keeps the
# genuinely low-ambiguity syntax (rm -rf, fork bombs, pipe-to-shell,
# credential-file exfiltration — all >= 0.88) while excluding single-word/
# low-specificity signals (sudo_elevation 0.70, chmod_world_writable 0.75)
# that are too common in benign prose to hard-block unconditionally.
_SHELL_DENY_MIN_CONFIDENCE = 0.85


def _expand_path(path: str) -> str:
    """Expand ~, normalise separators, and collapse ../ traversal segments
    lexically. A pentest found deny_path_patterns/credential detection
    trivially defeated by "/tmp/../etc/shadow"-shaped paths when this only
    expanded ~ without resolving ".." — posixpath.normpath (not os.path,
    since paths are always treated as POSIX-style here regardless of host
    OS) collapses that before any pattern comparison happens."""
    expanded = os.path.expanduser(path).replace("\\", "/")
    return posixpath.normpath(expanded).rstrip("/") or "/"


class PolicyEngine:
    """
    Synchronous, deterministic policy rule evaluator.

    Hot-reload supported via engine.reload(path).
    """

    def __init__(self, config: PolicyConfig | None = None, path: str | None = None) -> None:
        self._path: str | None
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
        self._shell_deny_patterns: list[re.Pattern[str]] = self._build_shell_deny_patterns()
        # Optional Rust fast-path: replaces Python regex loops when the native extension
        # is compiled and installed. Falls back to Python silently when unavailable.
        self._native = build_native_matcher(
            path_patterns=list(self._config.deny_path_patterns or []),
            domain_patterns=list(self._config.deny_domains or []),
            deny_tools=[t.lower() for t in (self._config.deny_tools or [])],
            allow_tools=[t.lower() for t in (self._config.allow_tools or [])],
            review_tools=[t.lower() for t in (self._config.review_tools or [])],
            unregistered_tools=[t.lower() for t in (self._config.deny_unregistered_tools or [])],
            provenance_patterns=list(self._config.deny_provenance_sources or []),
        )
        if RUST_AVAILABLE:
            logger.debug("policy_engine_native_matcher_active")

    def _build_shell_deny_patterns(self) -> list[re.Pattern[str]]:
        """Compile shell_command_policy's deny patterns — the operator's own
        explicit list if configured, else the built-in DESTRUCTIVE_SHELL set,
        filtered to _SHELL_DENY_MIN_CONFIDENCE and above.

        A code-review finding: every DESTRUCTIVE_SHELL pattern used to
        participate in this hard-BLOCK sweep regardless of its own
        confidence value, even though Rule 1.5 scans EVERY string-valued
        parameter of EVERY tool call unconditionally (see evaluate()'s Rule
        1.5 comment for why that's deliberate and not itself the bug).
        sudo_elevation (confidence 0.70 — bare "\\bsudo\\b") isn't
        objectively dangerous the way rm -rf or a fork bomb is; it's just a
        common word in ordinary technical writing ("Install with: sudo
        apt-get install foo"), so combined with the unconditional scan it
        hard-blocked routine Write calls whose *content* merely mentioned
        it. This module's own docstring already describes Rule 1.5 as "a
        fast lane for the obvious cases, not a replacement for semantic
        judgment on ambiguous ones" — a single common word is exactly the
        ambiguous case that fast lane was never meant to hard-block; it
        still reaches allow_tools/LLM risk scoring below like anything
        else. An operator's own explicit `deny_patterns` list is NOT
        filtered — those are raw strings with no confidence score, and an
        explicit config is an intentional opt-in this method shouldn't
        second-guess.
        """
        cfg = self._config.shell_command_policy
        if not cfg.enabled:
            return []
        if cfg.deny_patterns:
            return [re.compile(p, re.IGNORECASE) for p in cfg.deny_patterns]
        return [
            p.regex for p in patterns_for(DetectionCategory.DESTRUCTIVE_SHELL)
            if p.confidence >= _SHELL_DENY_MIN_CONFIDENCE
        ]

    @classmethod
    def from_yaml(cls, path: str) -> PolicyEngine:
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

        # .strip(): fnmatch.translate-compiled patterns are effectively
        # full-string matches (translate() end-anchors with \Z), so a tool
        # name with incidental leading/trailing whitespace — "bash " — used
        # to evade a deny_tools: ["bash"] rule entirely. A pentest found
        # this; whether it's exploitable depends on the calling SDK treating
        # "bash " and "bash" as the same tool for dispatch, but there's no
        # legitimate reason for a real tool name to carry surrounding
        # whitespace, so stripping here is a pure hardening with no
        # downside for well-formed callers.
        tool_lower = action.tool_name.strip().lower()

        # Rule 1: deny_tools
        if self._native:
            deny_hit = self._native.match_deny_tool(tool_lower)
        else:
            deny_hit = any(p.match(tool_lower) for p in self._deny_tool_patterns)
        if deny_hit:
            return Decision.BLOCK, _make_violation(
                "deny_tools", "tool_blacklist",
                f"Tool '{action.tool_name}' is in deny list",
                Decision.BLOCK, ra,
            )

        # Rule 1.5: shell_command_policy — content-aware destructive-command
        # pre-screen. Deliberately does NOT deny the "bash" tool by name
        # (that's what deny_tools is for, and it still runs first, above) —
        # this inspects the actual command string. A non-match falls
        # through to allow_tools/LLM scoring below, it is not treated as an
        # implicit ALLOW.
        #
        # Scans every string-valued parameter, recursively into nested
        # dicts/lists (iter_all_string_values), UNCONDITIONALLY — not gated
        # on action.type == SHELL_COMMAND. A pentest found that gate itself
        # a full bypass: infer_action_type() (action_types.py) only
        # recognizes a hardcoded lexicon of tool-name prefixes and parameter
        # keys (command/cmd/script); anything else — "input", "code",
        # "args" are all real conventions across different agent frameworks
        # — falls back to ActionType.TOOL_CALL, and this rule (gated on
        # SHELL_COMMAND) then never even ran regardless of how dangerous
        # the actual content was: {"tool_name": "run_task", "parameters":
        # {"input": "rm -rf /"}} sailed through as ALLOW. Classification is
        # an inherently-defeatable heuristic; enforcement must not depend
        # on it succeeding. Mirrors LocalClassifier._params_contain_injection's
        # already-proven approach to the identical problem.
        #
        # The one exception: ActionType.FILE_WRITE. A code-review finding —
        # a Write call whose *content* merely mentions "rm -rf build/" in a
        # README or script (ordinary, common documentation) hard-blocked
        # here even though nothing executes; writing text that looks like a
        # command poses no risk from the write itself. This is NOT the same
        # gap the classification-independence fix above closed: that was
        # about an action that actually EXECUTES a shell command hiding
        # under a nonstandard tool/parameter name (still caught regardless
        # of type, including TOOL_CALL/SHELL_COMMAND) — FILE_WRITE
        # specifically means "this is being persisted, not run," so
        # trusting it here doesn't reopen that exploit. If the written
        # content is later actually executed by a separate tool call, that
        # call's own command string is scanned independently when it
        # happens; a script's content sitting inert on disk is not.
        if self._shell_deny_patterns and action.type != ActionType.FILE_WRITE:
            for val in iter_all_string_values(action.parameters):
                for pattern in self._shell_deny_patterns:
                    if pattern.search(val):
                        return Decision.BLOCK, _make_violation(
                            "shell_command_policy", "shell_destructive_pattern",
                            f"Command matches destructive shell pattern ({pattern.pattern!r})",
                            Decision.BLOCK, ra,
                        )

        # Rule 2: allow_tools — if configured, tool MUST be in the allowlist
        if self._allow_tool_patterns:
            if self._native:
                in_allowlist = self._native.match_allow_tool(tool_lower)
            else:
                in_allowlist = any(p.match(tool_lower) for p in self._allow_tool_patterns)
            if not in_allowlist:
                return Decision.BLOCK, _make_violation(
                    "allow_tools", "tool_allowlist",
                    f"Tool '{action.tool_name}' is not in the allow list",
                    Decision.BLOCK, ra,
                )

        # Rule 3: deny_path_patterns — scans every string-valued parameter
        # (recursively), not gated on ActionType. Same classification-bypass
        # class as Rule 1.5: {"target": "~/.ssh/id_rsa"} never classifies as
        # FILE_READ (extract_file_path only recognizes path/file/filename/
        # filepath/file_path keys), so the old type-gated version of this
        # rule never ran regardless of the actual path.
        if self._path_patterns:
            for raw_val in iter_all_string_values(action.parameters):
                if len(raw_val) > _MAX_PATH_LEN:
                    continue
                if self._native:
                    matched_pattern = self._native.match_path(raw_val)
                    if matched_pattern:
                        return Decision.BLOCK, _make_violation(
                            "deny_path_patterns", "path_blacklist",
                            f"Path '{raw_val}' matches deny pattern '{matched_pattern}'",
                            Decision.BLOCK, ra,
                        )
                else:
                    expanded = _expand_path(raw_val)
                    for compiled, raw_pattern in self._path_patterns:
                        if compiled.fullmatch(expanded):
                            return Decision.BLOCK, _make_violation(
                                "deny_path_patterns", "path_blacklist",
                                f"Path '{raw_val}' matches deny pattern '{raw_pattern}'",
                                Decision.BLOCK, ra,
                            )

        # Rule 4: credential_access (belt-and-suspenders). Two independent
        # triggers, both preserved from before this fix plus one new one:
        #   (a) action.type == CREDENTIAL_ACCESS — classification already
        #       caught it, either via a recognized path key+is_credential_path,
        #       or via a tool-name pattern alone (credential/secret/vault/
        #       keychain — _TOOL_TYPE_PATTERNS in action_types.py) even when
        #       no parameter value looks path-shaped at all, e.g.
        #       {"secret_name": "db-password"}. That tool-name signal isn't
        #       otherwise derivable from scanning parameter values, so it's
        #       kept as-is rather than folded into the scan below.
        #   (b) NEW: any parameter value (recursively, any key) that matches
        #       is_credential_path — same classification-bypass class as
        #       Rules 1.5/3: {"target": "~/.ssh/id_rsa"} via a non-standard
        #       key never classified as CREDENTIAL_ACCESS, so (a) alone
        #       missed it.
        if action.type == ActionType.CREDENTIAL_ACCESS:
            path = extract_file_path(action.parameters)
            return Decision.BLOCK, _make_violation(
                "credential_access", "credential_pattern",
                f"Credential path detected: {path or action.tool_name}",
                Decision.BLOCK, ra,
            )
        for raw_val in iter_all_string_values(action.parameters):
            if len(raw_val) <= _MAX_PATH_LEN and is_credential_path(raw_val):
                return Decision.BLOCK, _make_violation(
                    "credential_access", "credential_pattern",
                    f"Credential path detected: {raw_val}",
                    Decision.BLOCK, ra,
                )

        # Rule 5: deny_domains — scans every string-valued parameter
        # (recursively) for URL/hostname-shaped content via iter_all_domains,
        # not just url/endpoint/uri/href keys, and not gated on ActionType.
        # Same classification-bypass class as Rules 1.5/3/4.
        if self._domain_patterns or self._native:
            for domain in iter_all_domains(action.parameters):
                if self._native:
                    matched_domain_pat = self._native.match_domain(domain)
                    if matched_domain_pat:
                        return Decision.BLOCK, _make_violation(
                            "deny_domains", "domain_blacklist",
                            f"Domain '{domain}' matches deny pattern '{matched_domain_pat}'",
                            Decision.BLOCK, ra,
                        )
                else:
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
        if self._native:
            review_hit = self._native.match_review_tool(tool_lower)
        else:
            review_hit = any(p.match(tool_lower) for p in self._review_tool_patterns)
        if review_hit:
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
            tool_lower = action.tool_name.strip().lower()
            if self._native:
                hit = self._native.match_unregistered_tool(tool_lower)
            else:
                hit = any(p.match(tool_lower) for p in self._unregistered_tool_patterns)
            if hit:
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
            if self._native:
                matched = self._native.match_provenance(tag.source_type.value)
                if matched:
                    return Decision.BLOCK, _make_violation(
                        "deny_provenance_sources", "provenance",
                        f"Action triggered by denied source '{tag.source_type.value}': {tag.label}",
                        Decision.BLOCK, ra,
                    )
            else:
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
