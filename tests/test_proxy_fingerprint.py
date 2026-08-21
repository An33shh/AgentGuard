"""Tests for agentguard.proxy.fingerprint.fingerprint_framework."""

from __future__ import annotations

from agentguard.proxy.fingerprint import detect_fingerprint_mismatch, fingerprint_framework


class TestNoSignal:
    def test_no_tools_no_user_agent_is_proxy(self) -> None:
        assert fingerprint_framework([], "") == "proxy"

    def test_empty_tool_names_filtered_out(self) -> None:
        assert fingerprint_framework(["", "", ""], "") == "proxy"


class TestUserAgentSignature:
    def test_claude_code_user_agent_matches_even_with_no_tools(self) -> None:
        assert fingerprint_framework([], "claude-code/2.1.89 (cli)") == "claude-code"

    def test_claude_cli_prefix_variant_matches(self) -> None:
        assert fingerprint_framework([], "claude-cli/1.0.0") == "claude-code"

    def test_user_agent_takes_priority_over_conflicting_tool_signature(self) -> None:
        # A client claiming a claude-code User-Agent but with an unrelated
        # toolset — UA still wins (tier ordering).
        assert fingerprint_framework(["search", "calculate"], "claude-code/2.1.89 (cli)") == "claude-code"

    def test_unrecognized_user_agent_falls_through(self) -> None:
        assert fingerprint_framework([], "python-httpx/0.27") == "proxy"

    def test_title_cased_user_agent_still_matches(self) -> None:
        # Case normalization must apply uniformly across all tiers, not
        # just the hash fallback — a gateway that title-cases the UA
        # shouldn't silently fragment into a different bucket.
        assert fingerprint_framework([], "Claude-Code/2.1.0 (CLI)") == "claude-code"


class TestToolSignature:
    def test_claude_code_marker_tools_match(self) -> None:
        tools = ["TodoWrite", "WebFetch", "Glob", "Grep", "Bash", "Read"]
        assert fingerprint_framework(tools, "") == "claude-code"

    def test_superset_of_markers_still_matches(self) -> None:
        # Version-bump tolerance: extra/unrelated tools don't break the match.
        tools = ["TodoWrite", "WebFetch", "Glob", "Grep", "SomeNewTool2026"]
        assert fingerprint_framework(tools, "") == "claude-code"

    def test_partial_marker_subset_does_not_match(self) -> None:
        tools = ["TodoWrite", "WebFetch"]  # missing Glob, Grep
        result = fingerprint_framework(tools, "")
        assert result != "claude-code"

    def test_lowercase_tool_names_still_match(self) -> None:
        # A client sending non-canonically-cased tool names ('todowrite'
        # instead of 'TodoWrite') must still match tier 2, not silently
        # fall through to the hash fallback.
        tools = ["todowrite", "webfetch", "glob", "grep"]
        assert fingerprint_framework(tools, "") == "claude-code"


class TestMalformedInputDefenseInDepth:
    """fingerprint_framework is a boundary function in its own right — other
    future call sites shouldn't have to re-derive format_handler.py's own
    isinstance guards."""

    def test_non_string_tool_names_ignored_without_raising(self) -> None:
        result = fingerprint_framework([123, None, True, "", "  "], "")  # type: ignore[list-item]
        assert result == "proxy"

    def test_mixed_valid_and_invalid_tool_names(self) -> None:
        result = fingerprint_framework(["TodoWrite", 123, "WebFetch", None, "Glob", "Grep"], "")  # type: ignore[list-item]
        assert result == "claude-code"

    def test_none_user_agent_does_not_raise(self) -> None:
        assert fingerprint_framework([], None) == "proxy"  # type: ignore[arg-type]


class TestDetectFingerprintMismatch:
    """UA-vs-tool-signature cross-validation — descriptive/audit only, see
    FingerprintSignalMismatch's docstring for why this never touches
    enforcement. The regression guard proving that end-to-end lives in
    tests/test_proxy_integration.py (test_fingerprint_mismatch_never_affects_decision)."""

    def test_corroborated_signals_produce_no_mismatch(self) -> None:
        result = detect_fingerprint_mismatch(
            ["TodoWrite", "WebFetch", "Glob", "Grep"], "claude-code/2.1.89 (cli)",
        )
        assert result is None

    def test_missing_markers_produce_a_mismatch(self) -> None:
        result = detect_fingerprint_mismatch(["search"], "claude-code/2.1.89 (cli)")
        assert result is not None
        assert result.claimed_framework == "claude-code"
        assert result.missing_markers == frozenset({"todowrite", "webfetch", "glob", "grep"})

    def test_no_tools_declared_is_not_a_mismatch(self) -> None:
        # A tool-less turn from a real client can't be verified either way
        # — must not read as evidence of spoofing.
        assert detect_fingerprint_mismatch([], "claude-code/2.1.89 (cli)") is None

    def test_no_user_agent_claim_is_not_a_mismatch(self) -> None:
        # Nothing to cross-check when the UA doesn't claim a known client.
        assert detect_fingerprint_mismatch(["TodoWrite"], "") is None
        assert detect_fingerprint_mismatch(["TodoWrite"], "python-httpx/0.27") is None

    def test_partial_marker_overlap_still_flags_missing_ones(self) -> None:
        result = detect_fingerprint_mismatch(["TodoWrite", "WebFetch"], "claude-code/2.1.89")
        assert result is not None
        assert result.missing_markers == frozenset({"glob", "grep"})

    def test_superset_of_markers_is_not_a_mismatch(self) -> None:
        tools = ["TodoWrite", "WebFetch", "Glob", "Grep", "Bash", "Read"]
        assert detect_fingerprint_mismatch(tools, "claude-code/2.1.89") is None

    def test_case_insensitive_matching(self) -> None:
        result = detect_fingerprint_mismatch(
            ["todowrite", "webfetch", "glob", "grep"], "Claude-Code/2.1.0 (CLI)",
        )
        assert result is None

    def test_malformed_tool_names_do_not_raise(self) -> None:
        result = detect_fingerprint_mismatch([123, None, "TodoWrite"], "claude-code/2.1.89")  # type: ignore[list-item]
        assert result is not None  # only "TodoWrite" survives filtering — still missing 3 markers


class TestUnknownFallbackHash:
    def test_unknown_toolset_produces_fingerprint_hash(self) -> None:
        result = fingerprint_framework(["search", "calculate"], "")
        assert result.startswith("unknown-fp-")

    def test_hash_is_deterministic_regardless_of_input_order(self) -> None:
        a = fingerprint_framework(["search", "calculate"], "")
        b = fingerprint_framework(["calculate", "search"], "")
        assert a == b

    def test_hash_is_case_invariant(self) -> None:
        a = fingerprint_framework(["Search", "Calculate"], "")
        b = fingerprint_framework(["search", "calculate"], "")
        assert a == b

    def test_different_toolsets_produce_different_hashes(self) -> None:
        a = fingerprint_framework(["search", "calculate"], "")
        b = fingerprint_framework(["fetch_url", "parse_html"], "")
        assert a != b
