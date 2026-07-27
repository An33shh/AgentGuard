"""
AgentGuard paper-2 hardening layer (research branch).

Closes the gaps identified against Dream Walking's threat model: per-action
signed approval binding, nonce-based replay rejection, and a hash-chained
tamper-evident event ledger.
"""

from agentguard.hardening.approval import ApprovalAuthority, ApprovalError
from agentguard.hardening.chained_ledger import ChainBrokenError, HashChainedEventLedger
from agentguard.hardening.models import ActionApproval, HardeningConfig, compute_action_hash
from agentguard.hardening.nonce_store import InMemoryNonceStore, NonceReplayError, NonceStore

__all__ = [
    "ActionApproval",
    "HardeningConfig",
    "compute_action_hash",
    "NonceStore",
    "InMemoryNonceStore",
    "NonceReplayError",
    "ApprovalAuthority",
    "ApprovalError",
    "HashChainedEventLedger",
    "ChainBrokenError",
]
