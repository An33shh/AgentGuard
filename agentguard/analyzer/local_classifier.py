"""Zero-latency pre-screen classifier — runs before LLM, zero API cost.

Catches high-confidence prompt injection attempts using pattern matching.
Returns a RiskAssessment immediately; returns None when ambiguous (→ escalate to LLM).
"""

from __future__ import annotations

from agentguard.analyzer.patterns import patterns_for
from agentguard.core.models import Action, RiskAssessment
from agentguard.guardrail.models import DetectionCategory

# Same semantic scope as before this module was consolidated onto the shared
# pattern registry (agentguard/analyzer/patterns.py) — prompt-injection and
# jailbreak signals only. See that module's docstring for why this exists
# instead of a private copy of the pattern list.
_INJECTION_PATTERNS = patterns_for(DetectionCategory.PROMPT_INJECTION, DetectionCategory.JAILBREAK)


def _params_contain_injection(parameters: dict) -> tuple[bool, str]:
    """Return (True, matched_pattern) if any parameter value contains an injection pattern."""
    for val in parameters.values():
        if not isinstance(val, str):
            continue
        for pattern in _INJECTION_PATTERNS:
            if pattern.regex.search(val):
                return True, pattern.name
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
        injected, _pattern = _params_contain_injection(action.parameters)
        if injected:
            return RiskAssessment(
                risk_score=self.INJECTION_SCORE,
                reason="Prompt injection pattern detected in action parameters",
                indicators=["prompt_injection", "local_classifier"],
                is_goal_aligned=False,
                analyzer_model="local_classifier",
            )
        return None
