"""Zero-latency pre-screen classifier — runs before LLM, zero API cost.

Catches high-confidence prompt injection attempts using pattern matching.
Returns a RiskAssessment immediately; returns None when ambiguous (→ escalate to LLM).
"""

from __future__ import annotations

import re

from agentguard.core.models import Action, RiskAssessment

# Unambiguous prompt injection signals in parameter values
_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.I)
    for p in [
        r"ignore\s+(previous|prior|all|your)\s+instructions?",
        r"override\s+(your|the|all|previous)\s+(goal|instruction|directive|system)",
        r"forget\s+(your|all|previous|prior)\s+instructions?",
        r"you\s+are\s+now\b",
        r"disregard\s+(all|your|previous|prior)",
        r"new\s+system\s+prompt",
        r"act\s+as\s+(if\s+you\s+are|a\s+)",
        r"\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>",
        r"do\s+not\s+follow\s+(your|the)\s+(guidelines?|instructions?|rules?)",
        r"bypass\s+(your\s+)?(safety|security|policy|restriction)",
        r"pretend\s+(you\s+are|to\s+be)",
        r"roleplay\s+as",
        r"\bjailbreak\b",
        r"\bDAN\b",
    ]
]


def _params_contain_injection(parameters: dict) -> tuple[bool, str]:
    """Return (True, matched_pattern) if any parameter value contains an injection pattern."""
    for val in parameters.values():
        if not isinstance(val, str):
            continue
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(val):
                return True, pattern.pattern
    return False, ""


class LocalClassifier:
    """
    Fast pre-screen before LLM analysis.

    Only classifies when confidence is very high (injection detected).
    Returns None for all ambiguous cases — LLM handles those.
    """

    INJECTION_SCORE = 0.92

    def classify(self, action: Action) -> RiskAssessment | None:
        """
        Return a high-confidence RiskAssessment or None (→ call LLM).
        """
        injected, pattern = _params_contain_injection(action.parameters)
        if injected:
            return RiskAssessment(
                risk_score=self.INJECTION_SCORE,
                reason="Prompt injection pattern detected in action parameters",
                indicators=["prompt_injection", "local_classifier"],
                is_goal_aligned=False,
                analyzer_model="local_classifier",
            )
        return None
