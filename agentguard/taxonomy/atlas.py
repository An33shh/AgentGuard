"""MITRE ATLAS technique registry — agentic AI relevant techniques."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class AtlasTactic(str, Enum):
    RECONNAISSANCE       = "Reconnaissance"
    INITIAL_ACCESS       = "Initial Access"
    EXECUTION            = "Execution"
    PERSISTENCE          = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION      = "Defense Evasion"
    CREDENTIAL_ACCESS    = "Credential Access"
    COLLECTION           = "Collection"
    EXFILTRATION         = "Exfiltration"
    IMPACT               = "Impact"
    LATERAL_MOVEMENT     = "Lateral Movement"
    DISCOVERY            = "Discovery"


@dataclass(frozen=True)
class AtlasTechnique:
    technique_id: str
    name: str
    tactic: AtlasTactic
    description: str

    @property
    def url(self) -> str:
        return f"https://atlas.mitre.org/techniques/{self.technique_id}"


ATLAS_TECHNIQUES: dict[str, AtlasTechnique] = {
    "AML.T0006": AtlasTechnique(
        "AML.T0006", "Active Scanning",
        AtlasTactic.RECONNAISSANCE,
        "Adversary scans for exposed ML infrastructure, model endpoints, or agent APIs",
    ),
    "AML.T0007": AtlasTechnique(
        "AML.T0007", "Discover ML Artifacts",
        AtlasTactic.RECONNAISSANCE,
        "Adversary discovers models, datasets, pipelines, or agent configurations",
    ),
    "AML.T0043": AtlasTechnique(
        "AML.T0043", "Craft Adversarial Data",
        AtlasTactic.EXECUTION,
        "Input crafted to manipulate model output or override agent behavior",
    ),
    "AML.T0048": AtlasTechnique(
        "AML.T0048", "Exfiltration via ML API",
        AtlasTactic.EXFILTRATION,
        "Sensitive data exfiltrated through model inference calls or agent tool outputs",
    ),
    "AML.T0049": AtlasTechnique(
        "AML.T0049", "Flooding",
        AtlasTactic.IMPACT,
        "Repeated requests exhaust compute budget, rate limits, or session capacity",
    ),
    "AML.T0051": AtlasTechnique(
        "AML.T0051", "LLM Prompt Injection",
        AtlasTactic.EXECUTION,
        "Malicious instructions injected into LLM prompt context to hijack agent behavior",
    ),
    "AML.T0054": AtlasTechnique(
        "AML.T0054", "Prompt Injection via Tool Outputs",
        AtlasTactic.EXECUTION,
        "Injected instructions arrive via tool or API output subsequently read by the agent",
    ),
    "AML.T0055": AtlasTechnique(
        "AML.T0055", "LLM Jailbreak",
        AtlasTactic.DEFENSE_EVASION,
        "Safety guardrails or system prompt constraints bypassed to override agent goals",
    ),
    "AML.T0056": AtlasTechnique(
        "AML.T0056", "LLM Meta Prompt Extraction",
        AtlasTactic.DISCOVERY,
        "System prompt, instructions, or internal tool schemas extracted from the model",
    ),
    "AML.T0057": AtlasTechnique(
        "AML.T0057", "LLM Data Leakage",
        AtlasTactic.EXFILTRATION,
        "Sensitive training data or context window content leaked through model outputs",
    ),
    "AML.T0058": AtlasTechnique(
        "AML.T0058", "Credential Access via Agent",
        AtlasTactic.CREDENTIAL_ACCESS,
        "Agent induced to read, transmit, or expose credentials, API keys, or secrets",
    ),
    "AML.T0059": AtlasTechnique(
        "AML.T0059", "Privilege Escalation via Agent",
        AtlasTactic.PRIVILEGE_ESCALATION,
        "Agent exploits identity ambiguity or token scope to gain elevated access",
    ),
    "AML.T0060": AtlasTechnique(
        "AML.T0060", "Lateral Movement via Agent",
        AtlasTactic.LATERAL_MOVEMENT,
        "Agent pivots to systems, services, or resources outside its authorized scope",
    ),
    "AML.T0061": AtlasTechnique(
        "AML.T0061", "Persistence via Agent Memory",
        AtlasTactic.PERSISTENCE,
        "Adversarial instructions written to persistent agent memory for future execution",
    ),
    "AML.T0062": AtlasTechnique(
        "AML.T0062", "Supply Chain Compromise of AI Agent",
        AtlasTactic.INITIAL_ACCESS,
        "Malicious tool, plugin, or MCP server injected into the agent toolchain",
    ),
}
