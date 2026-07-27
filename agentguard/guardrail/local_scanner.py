"""Zero-cost regex scanner for inbound prompt inspection.

Detects prompt injection, credential leaks, and PII in raw text.
Returns GuardrailDetection items with byte offsets — required for REDACT.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from agentguard.guardrail.models import DetectionCategory, GuardrailDetection

_SNIPPET_MAX = 80


@dataclass(frozen=True)
class _Pattern:
    name: str
    category: DetectionCategory
    regex: re.Pattern[str]
    confidence: float


def _p(
    name: str,
    pattern: str,
    category: DetectionCategory,
    confidence: float = 0.92,
    flags: int = re.I,
) -> _Pattern:
    return _Pattern(name=name, category=category, regex=re.compile(pattern, flags), confidence=confidence)


_PATTERNS: list[_Pattern] = [
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
    _p("dan_attack", r"\bDAN\b", DetectionCategory.JAILBREAK, flags=0),  # case-sensitive
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
]

# Group by category for enable/disable flags
_INJECTION_CATEGORIES = {DetectionCategory.PROMPT_INJECTION, DetectionCategory.JAILBREAK}
_CREDENTIAL_CATEGORIES = {DetectionCategory.CREDENTIAL}
_PII_CATEGORIES = {DetectionCategory.PII}


class LocalScanner:
    """
    Zero-cost regex scanner for raw text.

    Returns GuardrailDetection items with start/end offsets, enabling
    precise redaction without losing surrounding context.
    """

    def scan(
        self,
        text: str,
        scan_injection: bool = True,
        scan_credentials: bool = True,
        scan_pii: bool = True,
    ) -> list[GuardrailDetection]:
        detections: list[GuardrailDetection] = []

        for pat in _PATTERNS:
            if pat.category in _INJECTION_CATEGORIES and not scan_injection:
                continue
            if pat.category in _CREDENTIAL_CATEGORIES and not scan_credentials:
                continue
            if pat.category in _PII_CATEGORIES and not scan_pii:
                continue

            for m in pat.regex.finditer(text):
                snippet = m.group(0)
                if len(snippet) > _SNIPPET_MAX:
                    snippet = snippet[:_SNIPPET_MAX - 3] + "..."
                detections.append(
                    GuardrailDetection(
                        category=pat.category,
                        pattern_name=pat.name,
                        matched_snippet=snippet,
                        start_offset=m.start(),
                        end_offset=m.end(),
                        confidence=pat.confidence,
                    )
                )

        # Deduplicate overlapping spans (keep highest-confidence hit per span)
        return _deduplicate(detections)

    def redact(self, text: str, detections: list[GuardrailDetection]) -> str:
        """
        Replace detection spans with [REDACTED:<category>] placeholders.

        Processes right-to-left so earlier offsets remain valid after each substitution.
        Only redacts CREDENTIAL and PII — injection detections should BLOCK, not redact.
        """
        redactable = [
            d for d in detections
            if d.category in (_CREDENTIAL_CATEGORIES | _PII_CATEGORIES)
        ]
        # Sort descending by start offset
        redactable.sort(key=lambda d: d.start_offset, reverse=True)

        chars = list(text)
        for det in redactable:
            placeholder = f"[REDACTED:{det.category.value.upper()}]"
            chars[det.start_offset : det.end_offset] = list(placeholder)

        return "".join(chars)


def _deduplicate(detections: list[GuardrailDetection]) -> list[GuardrailDetection]:
    """Remove overlapping detections, keeping the highest-confidence hit per span."""
    if not detections:
        return detections

    # Sort by start offset, then by confidence descending
    sorted_dets = sorted(detections, key=lambda d: (d.start_offset, -d.confidence))
    result: list[GuardrailDetection] = []
    last_end = -1

    for det in sorted_dets:
        if det.start_offset >= last_end:
            result.append(det)
            last_end = det.end_offset

    return result
