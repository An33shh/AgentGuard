"""AgentGuard — Runtime detection and response platform for AI agents."""

from agentguard.core.models import Action, ActionType, Decision, Event, RiskAssessment
from agentguard.core.secure_agent import SecureAgent
from agentguard.core.exceptions import (
    AgentGuardError,
    BlockedByAgentGuard,
    PolicyViolationError,
    AnalyzerError,
)
from agentguard.guardrail import (
    PromptGuardrail,
    GuardrailConfig,
    GuardrailResult,
    GuardrailVerdict,
    ContextType,
    GuardrailMode,
)

__version__ = "0.5.0"
__all__ = [
    "Action",
    "ActionType",
    "Decision",
    "Event",
    "RiskAssessment",
    "SecureAgent",
    "AgentGuardError",
    "BlockedByAgentGuard",
    "PolicyViolationError",
    "AnalyzerError",
    "PromptGuardrail",
    "GuardrailConfig",
    "GuardrailResult",
    "GuardrailVerdict",
    "ContextType",
    "GuardrailMode",
]
