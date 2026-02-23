"""In-memory store for Claude-enriched security insights."""

from __future__ import annotations

from collections import OrderedDict
from typing import Any

from agentguard.integrations.enrichment import EnrichmentInsight


class InsightsStore:
    """Bounded in-memory store for enrichment insights, keyed by event_id."""

    def __init__(self, maxsize: int = 1000) -> None:
        self._store: OrderedDict[str, EnrichmentInsight] = OrderedDict()
        self._maxsize = maxsize

    def put(self, insight: EnrichmentInsight) -> None:
        if insight.event_id in self._store:
            del self._store[insight.event_id]
        self._store[insight.event_id] = insight
        if len(self._store) > self._maxsize:
            self._store.popitem(last=False)

    def get(self, event_id: str) -> EnrichmentInsight | None:
        return self._store.get(event_id)

    def list_recent(self, limit: int = 50) -> list[EnrichmentInsight]:
        items = list(self._store.values())
        return items[-limit:]

    def to_dict(self, insight: EnrichmentInsight) -> dict[str, Any]:
        return {
            "event_id": insight.event_id,
            "analysis": insight.analysis,
            "attack_patterns": insight.attack_patterns,
            "confidence": insight.confidence,
            "severity": insight.severity,
            "recommended_action": insight.recommended_action,
            "false_positive_likelihood": insight.false_positive_likelihood,
            "created_at": insight.created_at.isoformat(),
        }


_store: InsightsStore | None = None


def get_insights_store() -> InsightsStore:
    global _store
    if _store is None:
        _store = InsightsStore()
    return _store
