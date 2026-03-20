"""
Native Rust policy matcher — transparent Python fallback.

When the `agentguard_rs` Rust extension is compiled and installed (via maturin),
`RUST_AVAILABLE` is True and `build_native_matcher` returns a `PolicyMatcher` that
runs pattern matching in Rust (~5-10µs) instead of Python (~50µs).

When the extension is not available (e.g. fresh clone without Rust toolchain),
`build_native_matcher` returns None and the policy engine falls back to its
pre-compiled Python regexes — behaviour is identical.

Build instructions:
    cd agentguard_rs
    pip install maturin
    maturin develop --release   # installs into active venv
"""

from __future__ import annotations

from typing import Any

import structlog

_log = structlog.get_logger(__name__)

try:
    from agentguard_rs import PolicyMatcher as _RustPolicyMatcher  # type: ignore[import]

    RUST_AVAILABLE = True
    _log.debug("native_matcher_loaded", extension="agentguard_rs")
except ImportError:
    _RustPolicyMatcher = None  # type: ignore[assignment,misc]
    RUST_AVAILABLE = False


def build_native_matcher(
    path_patterns: list[str],
    domain_patterns: list[str],
    deny_tools: list[str],
    allow_tools: list[str],
    review_tools: list[str],
    unregistered_tools: list[str],
    provenance_patterns: list[str],
) -> Any | None:
    """
    Build a native Rust `PolicyMatcher` if the extension is available.

    Returns None when:
    - The Rust extension is not compiled/installed.
    - Construction raises any exception (e.g. invalid pattern — should not happen
      since patterns were already validated by PolicyConfig, but we fail safe).

    In both cases the caller falls back silently to Python compiled regexes.
    """
    if not RUST_AVAILABLE:
        return None
    try:
        return _RustPolicyMatcher(
            path_patterns,
            domain_patterns,
            deny_tools,
            allow_tools,
            review_tools,
            unregistered_tools,
            provenance_patterns,
        )
    except Exception as exc:  # pragma: no cover
        _log.warning("native matcher construction failed, using Python fallback: %s", exc)
        return None
