"""Unit tests for InsightsStore — deliberately not routed through the API,
since api/routes/insights.py uses a module-level singleton with no
dependency-injection override, and mutating that global from a test would
risk leaking state across the rest of the suite."""

from __future__ import annotations

from agentguard.integrations.enrichment import EnrichmentInsight
from agentguard.integrations.insights import InsightsStore


def _make_insight(event_id: str) -> EnrichmentInsight:
    return EnrichmentInsight(
        event_id=event_id,
        analysis="test analysis",
        attack_patterns=[],
        confidence=0.9,
        severity="low",
        recommended_action="none",
        false_positive_likelihood=0.1,
    )


def test_len_reflects_true_store_size_not_a_truncated_slice() -> None:
    store = InsightsStore(maxsize=1000)
    for i in range(5):
        store.put(_make_insight(f"event-{i}"))

    # list_recent's truncation must not be what callers use to report the
    # store's true total — regression guard for the "Showing N of N" bug,
    # where total was computed from the already-limited slice.
    truncated = store.list_recent(limit=2)
    assert len(truncated) == 2
    assert len(store) == 5


def test_len_respects_maxsize_eviction() -> None:
    store = InsightsStore(maxsize=3)
    for i in range(5):
        store.put(_make_insight(f"event-{i}"))
    assert len(store) == 3
