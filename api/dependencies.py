"""FastAPI dependency injection."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Annotated

from fastapi import Depends

from agentguard.analyzer.intent_analyzer import IntentAnalyzer
from agentguard.interceptor.interceptor import Interceptor
from agentguard.ledger.event_ledger import EventLedger, InMemoryEventLedger
from agentguard.policy.engine import PolicyEngine


@lru_cache
def get_ledger() -> EventLedger:
    """Get the global event ledger singleton.

    Returns InMemoryEventLedger for Phase 1.
    Swap the implementation here (and only here) to move to Phase 2 Postgres.
    """
    return InMemoryEventLedger()


@lru_cache
def get_policy_engine() -> PolicyEngine:
    """Get the global policy engine singleton."""
    policy_path = os.getenv("AGENTGUARD_POLICY_PATH", "policies/default.yaml")
    return PolicyEngine.from_yaml(policy_path)


@lru_cache
def get_interceptor() -> Interceptor:
    """Get the global interceptor singleton — shares the same ledger as the API."""
    return Interceptor(
        analyzer=IntentAnalyzer(
            api_key=os.getenv("ANTHROPIC_API_KEY"),
            model=os.getenv("AGENTGUARD_ANALYZER_MODEL", "claude-sonnet-4-6"),
        ),
        policy_engine=get_policy_engine(),
        event_ledger=get_ledger(),
    )


LedgerDep = Annotated[EventLedger, Depends(get_ledger)]
PolicyDep = Annotated[PolicyEngine, Depends(get_policy_engine)]
InterceptorDep = Annotated[Interceptor, Depends(get_interceptor)]
