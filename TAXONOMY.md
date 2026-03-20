# AgentGuard Threat Taxonomy

AgentGuard maps every security event to two industry-standard threat frameworks:

- **[MITRE ATLAS](https://atlas.mitre.org)** — technical adversarial ML technique IDs (`AML.Txxxx`) used internally by security engineers and SOC analysts
- **OWASP Agentic AI Top 10** — user-facing severity categories (`AA01`–`AA10`) for developers and risk teams

Every `PolicyViolation` carries `mitre_atlas_ids` and `owasp_categories` populated automatically by the policy engine. Enrichment-based `AttackTaxonomyAnnotation` fields on `RiskAssessment` are populated asynchronously after Claude triage.

---

## MITRE ATLAS Techniques

| ID | Name | Tactic | Description |
|---|---|---|---|
| AML.T0006 | Active Scanning | Reconnaissance | Adversary scans for exposed ML infrastructure, model endpoints, or agent APIs |
| AML.T0007 | Discover ML Artifacts | Reconnaissance | Adversary discovers models, datasets, pipelines, or agent configurations |
| AML.T0043 | Craft Adversarial Data | Execution | Input crafted to manipulate model output or override agent behavior |
| AML.T0048 | Exfiltration via ML API | Exfiltration | Sensitive data exfiltrated through model inference calls or agent tool outputs |
| AML.T0049 | Flooding | Impact | Repeated requests exhaust compute budget, rate limits, or session capacity |
| AML.T0051 | LLM Prompt Injection | Execution | Malicious instructions injected into LLM prompt context to hijack agent behavior |
| AML.T0054 | Prompt Injection via Tool Outputs | Execution | Injected instructions arrive via tool or API output subsequently read by the agent |
| AML.T0055 | LLM Jailbreak | Defense Evasion | Safety guardrails or system prompt constraints bypassed to override agent goals |
| AML.T0056 | LLM Meta Prompt Extraction | Discovery | System prompt, instructions, or internal tool schemas extracted from the model |
| AML.T0057 | LLM Data Leakage | Exfiltration | Sensitive training data or context window content leaked through model outputs |
| AML.T0058 | Credential Access via Agent | Credential Access | Agent induced to read, transmit, or expose credentials, API keys, or secrets |
| AML.T0059 | Privilege Escalation via Agent | Privilege Escalation | Agent exploits identity ambiguity or token scope to gain elevated access |
| AML.T0060 | Lateral Movement via Agent | Lateral Movement | Agent pivots to systems, services, or resources outside its authorized scope |
| AML.T0061 | Persistence via Agent Memory | Persistence | Adversarial instructions written to persistent agent memory for future execution |
| AML.T0062 | Supply Chain Compromise of AI Agent | Initial Access | Malicious tool, plugin, or MCP server injected into the agent toolchain |

---

## OWASP Agentic AI Top 10

| ID | Name | Description |
|---|---|---|
| AA01 | Prompt Injection & Goal Hijacking | External content overwrites agent goals or injects instructions that redirect behavior |
| AA02 | Insecure Tool Execution | Agent calls privileged or destructive tools without proper authorization or guardrails |
| AA03 | Sensitive Data Exfiltration | Agent reads and transmits credentials, PII, API keys, or proprietary data to unauthorized destinations |
| AA04 | Uncontrolled Autonomous Action | Agent takes high-impact, potentially irreversible actions without human oversight or approval |
| AA05 | Memory & Context Poisoning | Persistent memory stores or context windows corrupted by adversarial content for future exploitation |
| AA06 | Privilege Escalation | Agent exploits identity ambiguity, token scope, or role confusion to gain elevated access |
| AA07 | Supply Chain & Plugin Risks | Compromised tools, malicious MCP servers, or untrusted third-party plugins in the agent toolchain |
| AA08 | Lateral Movement | Agent pivots across systems, services, or data stores beyond its explicitly authorized scope |
| AA09 | Denial of Service & Resource Abuse | Flooding, infinite loops, or session abuse draining compute budgets or exhausting rate limits |
| AA10 | Insufficient Logging & Monitoring | Missing audit trails, opaque decision logs, or absent alerting that allow attacks to go undetected |

---

## Mapping Tables

### `attack_pattern` → Taxonomy

These `attack_pattern` values are produced by Claude enrichment triage (`agentguard/integrations/enrichment.py`).

| attack_pattern | MITRE ATLAS | OWASP |
|---|---|---|
| credential_exfiltration | AML.T0058, AML.T0048 | AA03, AA06 |
| data_exfiltration | AML.T0057, AML.T0048 | AA03 |
| prompt_injection | AML.T0051, AML.T0054 | AA01 |
| goal_hijacking | AML.T0051, AML.T0055 | AA01, AA04 |
| memory_poisoning | AML.T0061 | AA05 |
| privilege_escalation | AML.T0059 | AA06 |
| lateral_movement | AML.T0060 | AA08 |
| reconnaissance | AML.T0006, AML.T0007 | AA04 |
| none | — | — |

### `rule_type` → Taxonomy

These `rule_type` values are produced by the policy engine (`agentguard/policy/engine.py`).

| rule_type | MITRE ATLAS | OWASP |
|---|---|---|
| tool_blacklist | AML.T0051, AML.T0043 | AA02 |
| tool_allowlist | AML.T0051 | AA02 |
| path_blacklist | AML.T0058, AML.T0057 | AA03 |
| credential_pattern | AML.T0058 | AA03, AA06 |
| domain_blacklist | AML.T0048, AML.T0057 | AA03 |
| tool_review | AML.T0051 | AA04 |
| risk_score | — | AA04 |
| abac | AML.T0059 | AA06 |
| provenance | AML.T0054 | AA01 |
| session_max_actions | AML.T0049 | AA09 |
| session_max_blocked | AML.T0049 | AA09 |

---

## How to Add Custom Rule Annotations

Policy YAML files can override or extend the auto-detected taxonomy for any rule using the `rule_annotations` block. Keys correspond to `PolicyViolation.rule_name` values. Annotations are **merged (union)** with auto-detected IDs — they add to, never replace, the defaults.

```yaml
policy:
  name: "my-policy"
  # ... other settings ...

  rule_annotations:
    deny_tools:
      mitre_atlas_ids: ["AML.T0062"]
      owasp_categories: ["AA07"]
      notes: "Custom annotation — supply chain risk from untrusted MCP tools"
    credential_access:
      mitre_atlas_ids: ["AML.T0058"]
      owasp_categories: ["AA03", "AA06"]
      notes: "Credential path block per internal security policy ref: SEC-1234"
```

The `notes` field is for human-readable context and does not affect detection behavior.

---

## Implementation

- **Taxonomy module**: `agentguard/taxonomy/` — static Python data, zero external dependencies
- **Auto-annotation**: `agentguard/policy/engine.py` — `_make_violation()` factory annotates every block/review synchronously
- **Async enrichment annotation**: `agentguard/interceptor/interceptor.py` — `_enrich_direct()` attaches `AttackTaxonomyAnnotation` after Claude triage
- **Dashboard**: `dashboard/components/events/ThreatTaxonomyPanel.tsx` — MITRE ATLAS badges (clickable → atlas.mitre.org) + OWASP color-coded badges on every event detail page

---

*Intended as a community contribution to MITRE ATLAS agentic AI threat coverage. See [MITRE ATLAS Community Contributions](https://atlas.mitre.org/resources/contribute) for the contributor program.*
