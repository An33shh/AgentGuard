<div align="center">

```
 █████╗  ██████╗ ███████╗███╗   ██╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

**Runtime detection and response for AI agents.**

*CrowdStrike for AI agents. Not a prompt filter — secures autonomous decisions at runtime.*

[![PyPI](https://img.shields.io/pypi/v/agentguard?style=flat-square&logo=pypi&logoColor=white)](https://pypi.org/project/agentguard)
[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-174%20passing-22c55e?style=flat-square&logo=pytest&logoColor=white)](#)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-6366f1?style=flat-square)](#license)

</div>

---

Runtime security for AI agents. Intercepts every tool call before it executes — enforces YAML policies, scores intent with an LLM, and logs a forensic timeline.

```
AI Agent → AgentGuard → tool executes (or is blocked)
```

Works with any LLM — Claude, GPT-4o, Llama, Mistral, or anything running locally via Ollama or LM Studio. Native adapters for OpenAI Agents SDK, LangGraph, and OpenClaw. 174 tests passing.

---

## Where AgentGuard fits

[NVIDIA OpenShell](https://docs.nvidia.com/openshell/index.html) sandboxes agents at the OS level — Landlock filesystem rules, seccomp syscall filtering, per-binary network policy. It controls what an agent is *allowed to do*.

AgentGuard operates one layer up, inside the agent's execution pipeline. It understands *why* the agent wants to do something — scoring each action against the agent's declared goal using an LLM. An agent allowed to read files can still be caught attempting credential theft; an agent with valid network access can still be flagged for exfiltration behavior.

**The full stack — in execution order:**

```
Agent decides to call a tool
        ↓
AgentGuard  ← intercepts first, scores intent against goal (application layer)
        ↓  if allowed
Tool attempts to execute
        ↓
OpenShell   ← kernel-level backstop: Landlock, seccomp, network proxy
        ↓  if allowed
Action completes
```

AgentGuard runs *before* execution — a blocked action never reaches OpenShell.
OpenShell is the hard floor underneath: it catches anything that bypasses the
tool interface entirely (raw syscalls, forked subprocesses). Both layers are
needed; neither replaces the other.

---

## What it does

Every tool call passes through two gates before executing:

1. **Policy engine** — deterministic YAML rules (blocked tools, file paths, domains, session limits). Zero latency, no LLM required.
2. **Intent analyzer** — the configured LLM scores the action's risk (0–1) against the agent's stated goal. Blocks if above threshold.

Blocked events are stored with full forensic detail — risk score, reason, policy rule triggered, MITRE ATLAS technique, OWASP category — and visible in the dashboard.

---

## Install

### pip (recommended)

```bash
pip install agentguard
```

### Homebrew (macOS / Linux)

```bash
brew tap An33shh/agentguard
brew install agentguard
```

---

## Quickstart

### 1. Run the setup wizard

```bash
agentguard init
```

This walks you through choosing your LLM provider, entering your API key, and picking a database backend (SQLite for zero-setup local dev, Postgres for production). Creates a `.env` file in the current directory.

### 2. Start the API server

```bash
agentguard start
# API: http://localhost:8000
# Docs: http://localhost:8000/docs
```

### 3. Run the attack demo

```bash
agentguard demo
```

Runs 6 live scenarios through the guard — 5 attacks blocked (credential theft, data exfiltration, prompt injection, path traversal, domain blacklist), 1 legitimate action allowed.

### 4. Check status

```bash
agentguard status
```

Shows liveness + readiness for each component (database, Redis, policy engine, analyzer).

### 5. Start the dashboard (optional)

```bash
cd dashboard && npm install && npm run dev
# http://localhost:3000
```

---

### CLI reference

```
agentguard init      — interactive setup wizard (creates .env)
agentguard start     — start the API server
agentguard start --reload        — dev mode with auto-reload
agentguard start --port 9000     — custom port
agentguard demo      — run live attack scenario demo
agentguard status    — check API + component health
```

---

## Prerequisites

- Python 3.12+
- An API key for your chosen LLM provider (or Ollama running locally — no key needed)
- Node.js 18+ (dashboard only)
- Docker (Postgres + Redis) — or SQLite for zero-setup local dev

---

## Wrapping your agent

### OpenClaw (TypeScript ClawHub skill)

Copy `examples/openclaw_skill.ts` into your OpenClaw workspace skills directory:

```bash
export AGENTGUARD_API_URL=http://localhost:8000
```

```typescript
import { guardToolCall } from "./agentguard";

export const skill = {
  name: "file.read",
  async run({ path }: { path: string }, ctx: SkillContext) {
    await guardToolCall("file.read", { path }, ctx.agent.goal, ctx.session.id);
    return fs.readFileSync(path, "utf8");
  },
};
```

The skill calls `POST /api/v1/intercept` before execution. A `block` decision throws `AgentGuardBlockedError` — the tool never runs.

### OpenClaw (Python WebSocket path)

```python
from agentguard.core.secure_agent import SecureAgent
from agentguard.core.exceptions import BlockedByAgentGuard

guard   = SecureAgent.from_env(goal="Triage GitHub issues", framework="openclaw")
adapter = guard.get_openclaw_adapter()

async def on_tool_event(msg: dict) -> None:
    try:
        await adapter.before_tool_call(msg["skill"], msg.get("args", {}))
        # forward to OpenClaw gateway
    except BlockedByAgentGuard as exc:
        await deny_tool(msg["id"], reason=exc.event.assessment.reason)
```

### OpenAI Agents SDK

```python
from agentguard.core.secure_agent import SecureAgent
from agents import Runner

guard = SecureAgent.from_env(goal="Summarize the README file", framework="openai")
result = await Runner.run(agent, input=msg, hooks=guard.get_openai_hooks())
```

### LangGraph

```python
from agentguard.core.secure_agent import SecureAgent

guard = SecureAgent.from_env(goal="Research the latest news", framework="langgraph")
secured_graph = guard.wrap_langgraph(compiled_graph)
result = await secured_graph.ainvoke({"messages": [...]})
```

### Any framework (REST API)

Any runtime can call the intercept endpoint directly — Node.js, Go, or anything else:

```bash
curl -X POST http://localhost:8000/api/v1/intercept \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "file.read",
    "parameters": {"path": "~/.aws/credentials"},
    "goal": "Summarize the README file",
    "session_id": "my-session-001"
  }'
```

```json
{
  "decision": "block",
  "risk_score": 0.94,
  "reason": "Credential access inconsistent with stated goal",
  "event_id": "...",
  "mitre_technique": "credential_access",
  "owasp_category": "sensitive_data_exposure"
}
```

### Direct Python

```python
from agentguard.core.secure_agent import SecureAgent
from agentguard.core.models import Decision

guard = SecureAgent.from_env(goal="...")

decision, event = await guard.intercept({
    "tool_name": "file.read",
    "parameters": {"path": "/home/user/.aws/credentials"},
})

if decision == Decision.BLOCK:
    print(event.assessment.reason)
    # do not execute the tool call
```

---

## Switching LLM providers

AgentGuard defaults to Claude (`claude-sonnet-4-6`). Switch providers with two env vars:

**Anthropic (default)**
```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

**OpenAI**
```bash
export AGENTGUARD_ANALYZER=openai
export OPENAI_API_KEY=sk-...
export AGENTGUARD_ANALYZER_MODEL=gpt-4o
```

**Ollama (local, no API key)**
```bash
ollama pull llama3.1
export AGENTGUARD_ANALYZER=ollama
export AGENTGUARD_ANALYZER_MODEL=llama3.1
```

**Any OpenAI-compatible endpoint**
```bash
export AGENTGUARD_ANALYZER=openai
export AGENTGUARD_BASE_URL=https://your-endpoint/v1
export OPENAI_API_KEY=your-key
export AGENTGUARD_ANALYZER_MODEL=your-model
```

### Model quality and the security guarantee

The intent analyzer is the core of AgentGuard's behavioral detection. Its ability to catch
prompt injection, goal hijacking, and multi-step attack patterns depends entirely on the
reasoning quality of the configured model.

**Recommended models** (confirmed reliable for adversarial reasoning):

| Provider  | Recommended                          | Avoid                              |
|-----------|--------------------------------------|------------------------------------|
| Anthropic | `claude-sonnet-4-6` (**default**)    | claude-haiku-* (too weak)          |
| OpenAI    | `gpt-4o`, `gpt-4-turbo`             | gpt-3.5-*, gpt-4o-mini             |
| Groq      | `llama-3.3-70b-versatile`           | llama-3.2-* (< 70B)               |
| Local     | —                                    | Any quantized or <70B model        |

AgentGuard defaults to `claude-sonnet-4-6` because it provides the best adversarial reasoning
in its class. Switching to a weaker model does not just reduce accuracy — it creates a blind
spot that sophisticated attacks will exploit.

**When using a non-recommended model**, AgentGuard emits a `UserWarning` at startup:
```
UserWarning: AgentGuard: model 'llama3.1' (ollama) may not provide reliable adversarial
reasoning for security analysis. Recommended: claude-sonnet-4-6 (Anthropic) or gpt-4o (OpenAI).
```

The deterministic policy engine (deny_tools, path patterns, domains) is model-independent and
always fast. Only the LLM-scored `risk_threshold` gate degrades with weaker models.

---

## Policy configuration

Edit `policies/default.yaml`:

```yaml
policy:
  name: default
  risk_threshold: 0.75        # risk score at or above this → BLOCK
  review_threshold: 0.50      # between this and risk_threshold → REVIEW

  deny_tools:                 # always blocked, no LLM call made
    - shell.execute
    - bash.run
    - subprocess.run

  deny_path_patterns:         # file path globs, always blocked
    - ~/.ssh/**
    - ~/.aws/credentials
    - "**/*.pem"
    - "**/*.key"

  deny_domains:               # outbound HTTP domains, always blocked
    - "*.ngrok.io"
    - "*.requestbin.com"
    - webhook.site

  review_tools:               # flagged for human review, not auto-blocked
    - email.send
    - git.push
    - file.write

  session_limits:
    max_actions: 100
    max_blocked: 5            # session gets stricter thresholds after this many blocks
```

Hot-reload without restarting:

```bash
curl -X POST http://localhost:8000/api/v1/policies/reload
```

---

## Running tests

No API key required — the test suite mocks the LLM.

```bash
pytest tests/ -v
# 174 passed
```

---

## API reference

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/intercept` | Evaluate a tool call — returns decision before execution |
| `GET` | `/api/v1/events` | List events (filters: decision, risk, session, time) |
| `GET` | `/api/v1/events/{id}` | Full forensic detail for one event |
| `POST` | `/api/v1/events/search` | Full-text search over event reasons |
| `GET` | `/api/v1/timeline` | Ordered event timeline for a session |
| `GET` | `/api/v1/sessions` | List session IDs |
| `GET` | `/api/v1/agents` | Agent profiles with risk stats |
| `GET` | `/api/v1/agents/{id}/graph` | Knowledge graph (sessions, tools, attack patterns) |
| `GET` | `/api/v1/stats` | Aggregate counts and risk metrics |
| `GET` | `/api/v1/policies` | Active policy config |
| `POST` | `/api/v1/policies/reload` | Hot-reload policy from disk |
| `POST` | `/api/v1/policies/validate` | Validate YAML without applying |
| `GET` | `/api/v1/health` | Liveness probe |
| `GET` | `/api/v1/readiness` | Readiness probe (checks DB, Redis, policy engine) |
| `POST` | `/api/v1/demo/seed` | Seed example attack scenarios |

---

## Project structure

```
agentguard/
├── core/           Models, SecureAgent facade
├── interceptor/    Normalization + pipeline orchestration
├── analyzer/       LLM intent scoring (provider-agnostic backends)
├── policy/         YAML rule engine
├── ledger/         InMemoryEventLedger + PostgresEventLedger
├── adapters/       OpenAI Agents SDK + LangGraph + OpenClaw
├── auth/           JWT, rate limiting, ABAC
└── integrations/   Redis Streams, enrichment

api/                FastAPI application
dashboard/          Next.js 15 dashboard
policies/           default.yaml, strict.yaml
tests/              174 tests
examples/           demo_attack.py, openai_agent_example.py,
                    langgraph_agent_example.py, openclaw_agent_example.py,
                    openclaw_skill.ts
```

---

## License

MIT
