"""OWASP Agentic AI Top 10 — user-facing severity categories."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class OwaspCategory(str, Enum):
    AA01 = "AA01"
    AA02 = "AA02"
    AA03 = "AA03"
    AA04 = "AA04"
    AA05 = "AA05"
    AA06 = "AA06"
    AA07 = "AA07"
    AA08 = "AA08"
    AA09 = "AA09"
    AA10 = "AA10"


@dataclass(frozen=True)
class OwaspEntry:
    category: OwaspCategory
    name: str
    description: str


OWASP_ENTRIES: dict[OwaspCategory, OwaspEntry] = {
    OwaspCategory.AA01: OwaspEntry(
        OwaspCategory.AA01,
        "Prompt Injection & Goal Hijacking",
        "External content overwrites agent goals or injects instructions that redirect behavior",
    ),
    OwaspCategory.AA02: OwaspEntry(
        OwaspCategory.AA02,
        "Insecure Tool Execution",
        "Agent calls privileged or destructive tools without proper authorization or guardrails",
    ),
    OwaspCategory.AA03: OwaspEntry(
        OwaspCategory.AA03,
        "Sensitive Data Exfiltration",
        "Agent reads and transmits credentials, PII, API keys, or proprietary data to unauthorized destinations",
    ),
    OwaspCategory.AA04: OwaspEntry(
        OwaspCategory.AA04,
        "Uncontrolled Autonomous Action",
        "Agent takes high-impact, potentially irreversible actions without human oversight or approval",
    ),
    OwaspCategory.AA05: OwaspEntry(
        OwaspCategory.AA05,
        "Memory & Context Poisoning",
        "Persistent memory stores or context windows corrupted by adversarial content for future exploitation",
    ),
    OwaspCategory.AA06: OwaspEntry(
        OwaspCategory.AA06,
        "Privilege Escalation",
        "Agent exploits identity ambiguity, token scope, or role confusion to gain elevated access",
    ),
    OwaspCategory.AA07: OwaspEntry(
        OwaspCategory.AA07,
        "Supply Chain & Plugin Risks",
        "Compromised tools, malicious MCP servers, or untrusted third-party plugins in the agent toolchain",
    ),
    OwaspCategory.AA08: OwaspEntry(
        OwaspCategory.AA08,
        "Lateral Movement",
        "Agent pivots across systems, services, or data stores beyond its explicitly authorized scope",
    ),
    OwaspCategory.AA09: OwaspEntry(
        OwaspCategory.AA09,
        "Denial of Service & Resource Abuse",
        "Flooding, infinite loops, or session abuse draining compute budgets or exhausting rate limits",
    ),
    OwaspCategory.AA10: OwaspEntry(
        OwaspCategory.AA10,
        "Insufficient Logging & Monitoring",
        "Missing audit trails, opaque decision logs, or absent alerting that allow attacks to go undetected",
    ),
}
