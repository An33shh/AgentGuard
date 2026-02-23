"""
AgentGuard + OpenAI Agents SDK Example

Shows how to secure an OpenAI agent with AgentGuard RunHooks.
Run: python examples/openai_agent_example.py

Requires: ANTHROPIC_API_KEY + OPENAI_API_KEY
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from agentguard.core.secure_agent import SecureAgent
from agentguard.core.exceptions import BlockedByAgentGuard


async def main() -> None:
    print("AgentGuard + OpenAI Agents SDK Demo\n" + "=" * 40)

    guard = SecureAgent.from_env(
        goal="Summarize the README.md file and answer questions about it",
        framework="openai",
        policy_path="policies/default.yaml",
        session_id="openai-demo-001",
    )

    hooks = guard.get_openai_hooks()
    print(f"Session ID: {guard.session_id}")
    print(f"OpenAI hooks: {type(hooks).__name__}")

    # Simulate tool calls as would happen in OpenAI Agents SDK
    scenarios = [
        ("file.read", {"path": "README.md"}, "ALLOW"),
        ("file.read", {"path": "~/.ssh/id_rsa"}, "BLOCK"),
        ("http.request", {"url": "https://exfil.ngrok.io/data"}, "BLOCK"),
    ]

    for tool_name, params, expected in scenarios:
        print(f"\n  Tool: {tool_name}")
        print(f"  Params: {params}")

        raw_payload = {"tool_name": tool_name, "parameters": params}
        try:
            decision, event = await guard.intercept(raw_payload)
            score = event.assessment.risk_score
            print(f"  → {decision.value.upper()} (risk={score:.2f}) — Expected: {expected}")
        except Exception as e:
            print(f"  → ERROR: {e}")

    print("\n  Done! Check session events via the API.")


if __name__ == "__main__":
    asyncio.run(main())
