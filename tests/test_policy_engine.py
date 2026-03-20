"""Tests for the policy engine."""

from __future__ import annotations

import pytest

from agentguard.core.models import Action, ActionType, Decision
from agentguard.policy.engine import PolicyEngine
from agentguard.policy.schema import PolicyConfig


@pytest.fixture
def engine(default_policy_config: PolicyConfig) -> PolicyEngine:
    return PolicyEngine(config=default_policy_config)


def make_action(tool_name: str, params: dict, action_type: ActionType = ActionType.TOOL_CALL) -> Action:
    return Action(tool_name=tool_name, parameters=params, type=action_type)


class TestDenyTools:
    def test_blocks_shell_execute(self, engine: PolicyEngine) -> None:
        action = make_action("shell.execute", {"command": "ls"})
        decision, violation = engine.evaluate(action)
        assert decision == Decision.BLOCK
        assert violation is not None
        assert violation.rule_name == "deny_tools"

    def test_blocks_bash(self, engine: PolicyEngine) -> None:
        action = make_action("bash", {"command": "cat /etc/passwd"})
        decision, violation = engine.evaluate(action)
        assert decision == Decision.BLOCK

    def test_allows_file_read(self, engine: PolicyEngine) -> None:
        action = make_action("file.read", {"path": "README.md"}, ActionType.FILE_READ)
        decision, violation = engine.evaluate(action)
        assert decision == Decision.ALLOW
        assert violation is None


class TestDenyPathPatterns:
    def test_blocks_ssh_key(self, engine: PolicyEngine) -> None:
        action = make_action("file.read", {"path": "~/.ssh/id_rsa"}, ActionType.CREDENTIAL_ACCESS)
        decision, violation = engine.evaluate(action)
        assert decision == Decision.BLOCK

    def test_blocks_aws_credentials(self, engine: PolicyEngine) -> None:
        action = make_action("file.read", {"path": "~/.aws/credentials"}, ActionType.CREDENTIAL_ACCESS)
        decision, violation = engine.evaluate(action)
        assert decision == Decision.BLOCK

    def test_blocks_pem_file(self, engine: PolicyEngine) -> None:
        action = make_action("file.read", {"path": "/certs/server.pem"}, ActionType.CREDENTIAL_ACCESS)
        decision, violation = engine.evaluate(action)
        assert decision == Decision.BLOCK

    def test_allows_readme(self, engine: PolicyEngine) -> None:
        action = make_action("file.read", {"path": "README.md"}, ActionType.FILE_READ)
        decision, _ = engine.evaluate(action)
        assert decision == Decision.ALLOW


class TestDenyDomains:
    def test_blocks_ngrok(self, engine: PolicyEngine) -> None:
        action = make_action(
            "http.request",
            {"url": "https://abc123.ngrok.io/exfil"},
            ActionType.HTTP_REQUEST,
        )
        decision, violation = engine.evaluate(action)
        assert decision == Decision.BLOCK
        assert violation is not None
        assert violation.rule_name == "deny_domains"

    def test_blocks_requestbin(self, engine: PolicyEngine) -> None:
        action = make_action(
            "http.request",
            {"url": "https://xyz.requestbin.com/r/abc"},
            ActionType.HTTP_REQUEST,
        )
        decision, _ = engine.evaluate(action)
        assert decision == Decision.BLOCK

    def test_allows_github(self, engine: PolicyEngine) -> None:
        action = make_action(
            "http.request",
            {"url": "https://api.github.com/repos"},
            ActionType.HTTP_REQUEST,
        )
        decision, _ = engine.evaluate(action)
        assert decision == Decision.ALLOW


class TestRiskThreshold:
    def test_blocks_above_threshold(self, engine: PolicyEngine) -> None:
        decision, violation = engine.evaluate_risk(0.80)
        assert decision == Decision.BLOCK
        assert violation is not None
        assert violation.rule_name == "risk_threshold"

    def test_allows_below_threshold(self, engine: PolicyEngine) -> None:
        decision, violation = engine.evaluate_risk(0.50)
        assert decision == Decision.ALLOW

    def test_review_in_range(self, engine: PolicyEngine) -> None:
        decision, violation = engine.evaluate_risk(0.65)
        assert decision == Decision.REVIEW

    def test_blocks_at_threshold(self, engine: PolicyEngine) -> None:
        decision, _ = engine.evaluate_risk(0.75)
        assert decision == Decision.BLOCK


class TestReviewTools:
    def test_review_email_send(self, engine: PolicyEngine) -> None:
        action = make_action("email.send", {"to": "user@example.com"})
        decision, violation = engine.evaluate(action)
        assert decision == Decision.REVIEW
        assert violation is not None
        assert violation.rule_name == "review_tools"

    def test_review_git_push(self, engine: PolicyEngine) -> None:
        action = make_action("git.push", {"remote": "origin"})
        decision, _ = engine.evaluate(action)
        assert decision == Decision.REVIEW


class TestAllowTools:
    """allow_tools is a deny-by-default allowlist — unlisted tools must be blocked."""

    def test_allows_listed_tool(self) -> None:
        engine = PolicyEngine(config=PolicyConfig(
            name="allowlist-test",
            risk_threshold=0.75,
            review_threshold=0.60,
            allow_tools=["file.read", "web_search"],
        ))
        action = make_action("file.read", {"path": "README.md"}, ActionType.FILE_READ)
        decision, violation = engine.evaluate(action)
        assert decision == Decision.ALLOW
        assert violation is None

    def test_blocks_unlisted_tool(self) -> None:
        engine = PolicyEngine(config=PolicyConfig(
            name="allowlist-test",
            risk_threshold=0.75,
            review_threshold=0.60,
            allow_tools=["file.read"],
        ))
        action = make_action("email.send", {"to": "x@y.com"})
        decision, violation = engine.evaluate(action)
        assert decision == Decision.BLOCK
        assert violation is not None
        assert violation.rule_name == "allow_tools"

    def test_allowlist_with_wildcard(self) -> None:
        engine = PolicyEngine(config=PolicyConfig(
            name="allowlist-test",
            risk_threshold=0.75,
            review_threshold=0.60,
            allow_tools=["file.*"],
        ))
        decision, _ = engine.evaluate(make_action("file.read", {}, ActionType.FILE_READ))
        assert decision == Decision.ALLOW
        decision, _ = engine.evaluate(make_action("shell.execute", {}))
        assert decision == Decision.BLOCK

    def test_deny_tools_takes_priority_over_allow_tools(self) -> None:
        """deny_tools is evaluated before allow_tools — a tool in both lists is blocked."""
        engine = PolicyEngine(config=PolicyConfig(
            name="priority-test",
            risk_threshold=0.75,
            review_threshold=0.60,
            deny_tools=["bash"],
            allow_tools=["bash", "file.read"],
        ))
        action = make_action("bash", {"command": "ls"})
        decision, violation = engine.evaluate(action)
        assert decision == Decision.BLOCK
        assert violation.rule_name == "deny_tools"


class TestPolicyReload:
    def test_reload_from_yaml(self, tmp_path) -> None:
        import yaml
        policy_file = tmp_path / "test_policy.yaml"
        policy_data = {
            "policy": {
                "name": "reloaded",
                "risk_threshold": 0.80,
                "review_threshold": 0.60,
                "deny_tools": ["bad_tool"],
            }
        }
        policy_file.write_text(yaml.dump(policy_data))

        engine = PolicyEngine.from_yaml(str(policy_file))
        assert engine.config.name == "reloaded"
        assert engine.config.risk_threshold == 0.80

        # Modify and reload
        policy_data["policy"]["name"] = "reloaded_v2"
        policy_file.write_text(yaml.dump(policy_data))
        engine.reload()
        assert engine.config.name == "reloaded_v2"
