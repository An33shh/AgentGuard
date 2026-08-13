"""Zero-cost regex scanner for inbound prompt inspection.

Detects prompt injection, credential leaks, and PII in raw text.
Returns GuardrailDetection items with byte offsets — required for REDACT.

Patterns are sourced from agentguard.analyzer.patterns — the canonical,
shared registry that replaced this module's own private copy (which had
already drifted from agentguard/analyzer/local_classifier.py's copy before
the consolidation; see that module's docstring for why).
"""

from __future__ import annotations

from agentguard.analyzer.patterns import DetectionCategory, patterns_for
from agentguard.guardrail.models import GuardrailDetection

_SNIPPET_MAX = 80

# Group by category for enable/disable flags
_INJECTION_CATEGORIES = {DetectionCategory.PROMPT_INJECTION, DetectionCategory.JAILBREAK}
_CREDENTIAL_CATEGORIES = {DetectionCategory.CREDENTIAL}
_PII_CATEGORIES = {DetectionCategory.PII}

_PATTERNS = patterns_for(
    DetectionCategory.PROMPT_INJECTION,
    DetectionCategory.JAILBREAK,
    DetectionCategory.CREDENTIAL,
    DetectionCategory.PII,
)


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
