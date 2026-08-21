"""Canonical regex pattern registry — single source of truth for every
deterministic (zero-LLM-cost) text/content pattern used across AgentGuard.

Consolidates what used to be two independently-maintained, already-drifted
copies of the same prompt-injection/jailbreak pattern list
(agentguard/analyzer/local_classifier.py and agentguard/guardrail/local_scanner.py),
plus new destructive-shell-command patterns for policy-engine Bash
content-screening. Consumers filter this one list by DetectionCategory
rather than maintaining their own pattern sets, so a fix/addition made here
is automatically visible everywhere it's relevant instead of requiring the
same edit in N places.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class DetectionCategory(str, Enum):
    """
    Defined here, not in agentguard.guardrail.models, deliberately: this
    module must be a leaf with no dependency on the guardrail package, since
    agentguard/guardrail/__init__.py eagerly imports PromptGuardrail ->
    local_scanner.py -> this module. guardrail.models re-exports this name
    for backward compatibility — import it from either location.
    """

    PROMPT_INJECTION = "prompt_injection"
    CREDENTIAL = "credential"
    PII = "pii"
    JAILBREAK = "jailbreak"
    DESTRUCTIVE_SHELL = "destructive_shell"


@dataclass(frozen=True)
class Pattern:
    name: str
    category: DetectionCategory
    regex: re.Pattern[str]
    confidence: float


def _p(
    name: str,
    pattern: str,
    category: DetectionCategory,
    confidence: float = 0.92,
    flags: int = re.IGNORECASE,
) -> Pattern:
    return Pattern(name=name, category=category, regex=re.compile(pattern, flags), confidence=confidence)


PATTERNS: list[Pattern] = [
    # ── Prompt injection ─────────────────────────────────────────────────────
    _p("ignore_previous_instructions", r"ignore\s+(previous|prior|all|your)\s+instructions?", DetectionCategory.PROMPT_INJECTION),
    _p("override_goal_or_system", r"override\s+(your|the|all|previous)\s+(goal|instruction|directive|system)", DetectionCategory.PROMPT_INJECTION),
    _p("forget_instructions", r"forget\s+(?:(?:your|all|previous|prior)\s+)+instructions?", DetectionCategory.PROMPT_INJECTION),
    _p("you_are_now", r"you\s+are\s+now\b", DetectionCategory.PROMPT_INJECTION),
    _p("disregard", r"disregard\s+(all|your|previous|prior)", DetectionCategory.PROMPT_INJECTION),
    _p("new_system_prompt", r"new\s+system\s+prompt", DetectionCategory.PROMPT_INJECTION),
    _p("act_as", r"act\s+as\s+(if\s+you\s+are|a\s+)", DetectionCategory.PROMPT_INJECTION),
    _p("do_not_follow_guidelines", r"do\s+not\s+follow\s+(your|the)\s+(guidelines?|instructions?|rules?)", DetectionCategory.PROMPT_INJECTION),
    _p("bypass_safety", r"bypass\s+(your\s+)?(safety|security|policy|restriction)", DetectionCategory.PROMPT_INJECTION),
    _p("pretend_to_be", r"pretend\s+(you\s+are|to\s+be)", DetectionCategory.PROMPT_INJECTION),
    _p("roleplay_as", r"roleplay\s+as", DetectionCategory.PROMPT_INJECTION),
    # ── Jailbreak ────────────────────────────────────────────────────────────
    _p("jailbreak_keyword", r"\bjailbreak\b", DetectionCategory.JAILBREAK),
    # Case-sensitive deliberately, not an oversight: "DAN" case-insensitive
    # would false-positive on the common first name "Dan" in ordinary text.
    # (Consolidating local_classifier.py onto this shared list made it adopt
    # this — local_classifier.py's old private copy was case-insensitive,
    # which was itself the less-considered choice, not this one.)
    _p("dan_attack", r"\bDAN\b", DetectionCategory.JAILBREAK, flags=0),
    # Case-sensitive for the same reason — real [INST]/<|im_start|> template
    # tokens are exact-case; case-insensitive matching risks false positives
    # on unrelated lowercase text.
    _p("llm_token_injection", r"\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>", DetectionCategory.JAILBREAK, flags=0),
    # ── Credentials ──────────────────────────────────────────────────────────
    _p("anthropic_openai_key", r"(?:sk-ant-|sk-)[A-Za-z0-9\-_]{20,}", DetectionCategory.CREDENTIAL, confidence=0.98, flags=0),
    _p("github_token", r"(?:ghp_|gho_|github_pat_)[A-Za-z0-9]{36,}", DetectionCategory.CREDENTIAL, confidence=0.98, flags=0),
    _p("aws_access_key", r"AKIA[0-9A-Z]{16}", DetectionCategory.CREDENTIAL, confidence=0.98, flags=0),
    _p("private_key_header", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", DetectionCategory.CREDENTIAL, confidence=0.99),
    _p("plaintext_credential", r'(?:password|passwd|secret|api[_\-]?key|token)\s*[=:]\s*[\'\"]\S{8,}[\'\"]', DetectionCategory.CREDENTIAL, confidence=0.85),
    # ── PII ──────────────────────────────────────────────────────────────────
    _p("us_ssn", r"\b\d{3}-\d{2}-\d{4}\b", DetectionCategory.PII, confidence=0.80),
    _p("email_address", r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", DetectionCategory.PII, confidence=0.75),
    _p("us_phone", r"\b(?:\+1[\s\-.]?)?\(?\d{3}\)?[\s\-\.]\d{3}[\s\-\.]\d{4}\b", DetectionCategory.PII, confidence=0.70),
    _p("credit_card", r"\b(?:\d[ \-]?){13,16}\b", DetectionCategory.PII, confidence=0.60),
    # ── Destructive shell commands (agentguard/policy/engine.py's
    # ShellCommandPolicy pre-screen — see the WS2 plan for why this replaces
    # the old blanket deny_tools:[bash] ban) ──────────────────────────────────
    # Lookaheads (not a single contiguous flag token) so recursive+force are
    # caught regardless of order, spacing, or short/long-option spelling:
    # "-rf", "-fr", "-r -f", "-f -r", "--recursive --force", "-r --force",
    # etc. A pentest found the old single-token regex trivially defeated by
    # any of those — split flags or GNU long options. `(?<!-)` excludes "rm"
    # appearing mid-compound-word (e.g. a filename like "notes-about-rm
    # -rf.txt") — this rule now scans every parameter value unconditionally
    # (see engine.py's Rule 1.5), so without this it false-positived on
    # ordinary text/filenames that happen to contain "-rm" as a substring.
    _p(
        "rm_recursive_force",
        r"(?<!-)\brm\s+(?=.*(?:-[a-zA-Z]*r[a-zA-Z]*\b|--recursive\b))(?=.*(?:-[a-zA-Z]*f[a-zA-Z]*\b|--force\b)).+",
        DetectionCategory.DESTRUCTIVE_SHELL, confidence=0.90, flags=0,
    ),
    _p("fork_bomb", r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", DetectionCategory.DESTRUCTIVE_SHELL, confidence=0.97, flags=0),
    _p("pipe_remote_to_shell", r"(curl|wget)\s+.*\|\s*(sudo\s+)?(sh|bash|zsh)\b", DetectionCategory.DESTRUCTIVE_SHELL, confidence=0.88),
    # "Fetch to a file, then execute that same file" without a pipe — e.g.
    # `curl url -o x.sh && bash x.sh`. A pentest found the pipe-only pattern
    # above defeated by this equally-common two-step form. Backreference
    # requires the executed path to match the downloaded path exactly, so
    # unrelated "download data, then run an unrelated script" sequences
    # (a common, benign CI/build pattern) don't false-positive.
    _p(
        "fetch_then_exec",
        r"(curl|wget)\s+.*?(?:-o|-O|--output)\s+(\S+).*?(?:&&|;|\n)\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|perl|ruby|node)\s+\2\b",
        DetectionCategory.DESTRUCTIVE_SHELL, confidence=0.88,
    ),
    # chmod_world_writable and sudo_elevation are deliberately NOT in this
    # list — see _SHELL_DENY_MIN_CONFIDENCE's comment in policy/engine.py.
    # Both are still registered here (harmless, patterns_for() callers
    # filter by category+confidence) for guardrail/local_classifier reuse
    # if a future consumer wants them at a different bar.
    _p("chmod_world_writable", r"\bchmod\s+(-[a-zA-Z]+\s+)?[0-7]*777\b", DetectionCategory.DESTRUCTIVE_SHELL, confidence=0.75, flags=0),
    _p("dd_disk_write", r"\bdd\s+.*\bof=/dev/", DetectionCategory.DESTRUCTIVE_SHELL, confidence=0.93, flags=0),
    _p("sudo_elevation", r"\bsudo\b", DetectionCategory.DESTRUCTIVE_SHELL, confidence=0.70, flags=0),
    # A code-review finding: this codebase's own credential_access rule
    # (policy/engine.py Rule 5, is_credential_path()) is NOT a superset of
    # what the shell_ssh_key_access / shell_aws_credential_access /
    # shell_shadow_sudoers_access patterns previously here covered, despite
    # a comment that used to claim it was — is_credential_path only matches
    # a parameter value that IS (or ends with) a credential path, not one
    # that CONTAINS one alongside other shell syntax. "cat ~/.ssh/id_rsa >
    # /tmp/exfil" evaded it entirely; live-verified against the native
    # matcher. Restored here as a single pattern rather than three, scoped
    # to require an actual shell read/transfer verb before the credential
    # path (not just a bare path) specifically so it does NOT re-trigger
    # the original mis-attribution problem: a plain file.read action whose
    # only parameter value IS the bare path "~/.ssh/id_rsa" has no verb to
    # match, so it still falls through to Rule 5/credential_access as
    # before, not "stolen" by this rule ahead of it. .ssh/.aws match the
    # directory itself (not just specific filenames within it), since
    # `tar -czf - ~/.aws | base64` exfiltrates the whole directory, not one
    # named file.
    _p(
        "shell_credential_exfiltration",
        r"\b(?:cat|less|more|head|tail|cp|mv|scp|rsync|nc|ncat|socat|base64|xxd|od"
        r"|tar|zip|gzip|curl|wget|mail|sendmail|python3?|perl|ruby|node)\b[^\n]*"
        r"(?:\.ssh\b|\.aws\b|/etc/(?:passwd|shadow|sudoers)\b|\.netrc\b|credentials\.json\b)",
        DetectionCategory.DESTRUCTIVE_SHELL, confidence=0.88,
    ),
]


def patterns_for(*categories: DetectionCategory) -> list[Pattern]:
    """Return the subset of PATTERNS matching any of the given categories."""
    wanted = set(categories)
    return [p for p in PATTERNS if p.category in wanted]
