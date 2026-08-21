"""
Framework fingerprinting for AUTO-DETECTED (unregistered) proxy agents.

Feeds the existing derive_agent_id(agent_goal, framework) machinery in
agentguard/core/models.py — this is not a new identity system. Output is
heuristic and spoofable by design: it only ever resolves the `framework`
label, never `agent_id`, so it can never upgrade an unregistered agent to
registered (see Interceptor.intercept()'s is_registered = bool(agent_id),
which depends solely on the caller-supplied X-AgentGuard-AgentId header).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

# (User-Agent substring, framework label) — checked in order, first match
# wins. Needles kept lowercase — compared against a lowercased UA below.
# Claude Code CLI sends "claude-code/<version> (cli)"; some gateways match
# on the "claude-cli" prefix too — cover both. TODO: verify Codex CLI's
# actual UA on its /v1/chat/completions calls (not its MCP client, which is
# a different code path) before adding an entry for it.
KNOWN_UA_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("claude-code/", "claude-code"),
    ("claude-cli", "claude-code"),
)

# framework label -> marker tool names (lowercased) that must ALL be present
# (subset containment, not full-set equality) — tolerant of the client
# adding/removing unrelated tools between versions. Keep markers few and
# distinctive to bound false-positive collision risk.
KNOWN_TOOL_SIGNATURES: dict[str, frozenset[str]] = {
    "claude-code": frozenset({"todowrite", "webfetch", "glob", "grep"}),
}

_FALLBACK_HASH_LEN = 12  # 48 bits — between derive_agent_id's 6-char md5
                         # suffix and dependencies.py's 16-char auth hash.


def fingerprint_framework(tool_names: list[str], user_agent: str = "") -> str:
    """
    Resolve a stable `framework` label for an unheadered proxy client.

    Order: known UA signature -> known tool-name signature (subset match)
    -> raw hash of the full sorted tool-name set -> "proxy" (no signal).

    Normalizes case uniformly across all three tiers (not just the hash
    fallback) — otherwise a title-cased User-Agent or non-canonically-cased
    tool names silently miss tiers 1/2 and fall all the way to "proxy",
    fragmenting one real client across multiple dashboard buckets.
    """
    ua = (user_agent or "").strip().lower()
    for needle, label in KNOWN_UA_SIGNATURES:
        if needle in ua:
            return label

    names = {
        n.strip().lower() for n in (tool_names or [])
        if isinstance(n, str) and n.strip()
    }
    if not names:
        return "proxy"

    for label, markers in KNOWN_TOOL_SIGNATURES.items():
        if markers <= names:
            return label

    canonical = ",".join(sorted(names))
    digest = hashlib.sha256(canonical.encode()).hexdigest()[:_FALLBACK_HASH_LEN]
    return f"unknown-fp-{digest}"


@dataclass(frozen=True)
class FingerprintSignalMismatch:
    """
    Disagreement between the User-Agent-claimed framework and the request's
    own declared tool names. Meaningful because copying a UA string is
    trivial; copying a client's exact tool schema is a materially higher
    bar — but this is PURELY a descriptive/audit signal. It never feeds
    framework resolution, derive_agent_id, or any enforcement path (see
    fingerprint_framework's docstring and the Finding-1 fix in pipeline.py
    for why that boundary is load-bearing). Consumers: structured logging
    and ProvenanceTag only — never GuardrailDetection/PolicyEngine/ABAC.
    """
    claimed_framework: str
    observed_tool_names: frozenset[str]
    missing_markers: frozenset[str]


def detect_fingerprint_mismatch(
    tool_names: list[str], user_agent: str = "",
) -> FingerprintSignalMismatch | None:
    """
    None when there's nothing to check: UA doesn't claim a known client,
    no marker signature is registered for the claimed label, or — notably —
    no tools were declared at all (a tool-less turn from a real client
    can't be verified either way and must not read as evidence of
    spoofing). Otherwise, non-None iff the UA's claimed label's marker set
    isn't a subset of the request's actual (lowercased) tool names.
    """
    ua = (user_agent or "").strip().lower()
    claimed = next((label for needle, label in KNOWN_UA_SIGNATURES if needle in ua), None)
    if claimed is None:
        return None

    markers = KNOWN_TOOL_SIGNATURES.get(claimed)
    if not markers:
        return None

    names = {n.strip().lower() for n in (tool_names or []) if isinstance(n, str) and n.strip()}
    if not names:
        return None

    missing = markers - names
    if not missing:
        return None

    return FingerprintSignalMismatch(
        claimed_framework=claimed,
        observed_tool_names=frozenset(names),
        missing_markers=frozenset(missing),
    )
