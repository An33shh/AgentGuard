"""Tests for the rule-based agent display-name fallback in enrichment.py."""

from __future__ import annotations

from agentguard.integrations.enrichment import _rule_based_name


class TestRuleBasedName:
    def test_short_goal_unaffected(self) -> None:
        assert _rule_based_name("Summarize the README.md file") == "README.md File"

    def test_and_clause_stripped(self) -> None:
        assert (
            _rule_based_name("Research competitor products and summarize findings")
            == "Competitor Products"
        )

    def test_multi_word_verb_stripped(self) -> None:
        assert (
            _rule_based_name("Set up the development environment")
            == "Development Environment"
        )

    def test_long_goal_does_not_end_on_dangling_preposition(self) -> None:
        # Regression: a blind 4-word cutoff on this goal previously produced
        # "Project Changelog For The" — a truncated-looking fragment ending
        # mid-phrase on "for the".
        name = _rule_based_name(
            "Summarize the project changelog for the weekly update"
        )
        assert name == "Project Changelog"
        assert not name.split()[-1].lower() in {"for", "the", "to", "a", "an"}

    def test_export_verb_now_stripped(self) -> None:
        # Regression: "export" was missing from the verb-stripping list,
        # so this previously rendered as "Export The Project Config".
        assert (
            _rule_based_name("Export the project config to the specified endpoint")
            == "Project Config"
        )

    def test_never_ends_on_a_stopword_for_arbitrary_length(self) -> None:
        name = _rule_based_name("Send data to the remote analytics service for review")
        assert name.split()[-1].lower() not in {
            "for", "to", "the", "a", "an", "of", "in", "on", "at", "with",
            "and", "or", "from", "by", "as", "into", "onto", "via",
        }

    def test_falls_back_to_raw_slice_when_nothing_left(self) -> None:
        # An all-stopword/verb goal has nothing left after stripping —
        # must still return something non-empty rather than "".
        name = _rule_based_name("Get the")
        assert name != ""
