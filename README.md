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

[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-586%20passing-22c55e?style=flat-square&logo=pytest&logoColor=white)](#running-tests)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-6366f1?style=flat-square)](#license)

</div>

---

Runtime security for AI agents. Intercepts every tool call before it executes — enforces policy, scores intent against the agent's stated goal, and logs a forensic timeline.

```
AI Agent → AgentGuard → tool executes (or is blocked)
```

Works with any LLM — Claude, GPT-4o, Llama, Mistral, or anything running locally via Ollama or LM Studio. Native adapters for OpenAI Agents SDK, LangGraph, and OpenClaw. 586 tests passing.

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

## LLM API proxy

For agents you can't (or don't want to) instrument with an adapter, AgentGuard can also run as a
drop-in reverse proxy in front of the real Anthropic and OpenAI APIs — point your existing SDK's
base URL at it, keep your real API key, and every tool/function call is intercepted with no
changes to agent code.

```
Agent SDK  →  AgentGuard proxy  →  api.anthropic.com / api.openai.com
```

- Supports both `/v1/messages` (Anthropic) and `/v1/chat/completions` (OpenAI-compatible), streaming and non-streaming.
- Scans inbound content for prompt injection before it reaches the agent.
- Buffers only tool-call content from the response — everything else streams through live, so a
  blocked tool call is replaced with a text explanation instead of executing or silently vanishing.
- Fails closed: an unhandled proxy error blocks the request rather than passing it through unfiltered.
- Runs as its own service on its own port, separate from the main API.

```bash
export AGENTGUARD_PROXY_ANTHROPIC_BASE_URL=https://api.anthropic.com
export AGENTGUARD_PROXY_OPENAI_BASE_URL=https://api.openai.com
uvicorn agentguard.proxy.app:app --port 8748
```

Point your SDK's `base_url` at `http://localhost:8748` and call it exactly as you would the real
API — your normal API key is forwarded upstream unchanged. Optional headers give AgentGuard
context it can't infer from the request alone:

```
X-AgentGuard-Goal:       "Summarize the README file"   # agent's stated goal, scored against each action
X-AgentGuard-AgentId:    my-registered-agent-id          # explicit identity (skips ABAC's unregistered-caller checks)
X-AgentGuard-Framework:  langgraph                       # declared framework, used if auto-detection is inconclusive
```

Not yet published as a container image or `docker-compose` service — run it directly with `uvicorn` as shown above, or behind your own process manager.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/messages` | Anthropic Messages API, streaming and non-streaming |
| `POST` | `/v1/chat/completions` | OpenAI Chat Completions API, streaming and non-streaming |
| `GET` | `/admin/sessions/{session_id}` | Session's action/blocked counters and lockout status |
| `POST` | `/admin/sessions/{session_id}/reset` | Clear a session's counters, lifting a lockout |

`/admin/*` requires the same auth as the main API (`AGENTGUARD_API_KEY` / JWT) when configured.

---

## Install

A PyPI package and Homebrew tap are planned but not published yet — for now, install from source:

```bash
git clone https://github.com/An33shh/AgentGuard.git
cd AgentGuard
pip install -e .
```

This installs the `agentguard` CLI on your `PATH`.

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
# API: http://localhost:8747
# Docs: http://localhost:8747/docs
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
# http://localhost:3747
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
export AGENTGUARD_API_URL=http://localhost:8747
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
curl -X POST http://localhost:8747/api/v1/intercept \
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
  "risk_score": 0.95,
  "reason": "Policy rule 'deny_path_patterns' triggered: Path '~/.aws/credentials' matches deny pattern '~/.aws/credentials'",
  "event_id": "...",
  "mitre_technique": "AML.T0058",
  "owasp_category": "AA03"
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
prompt injection, goal hijacking, and multi-step attack patterns depends on the reasoning
quality of the configured model — use a frontier-class reasoning model for the analyzer
(AgentGuard defaults to `claude-sonnet-4-6`), not a distilled, "mini," or small (<70B) variant.
A weaker model doesn't just reduce accuracy; it narrows what the analyzer can reliably catch.

AgentGuard emits a `UserWarning` at startup when the configured model falls outside its known-good list, so a weak-model deployment is loud, not silent.

The deterministic policy engine (blocked tools, path patterns, domains) is model-independent and
always fast — it doesn't depend on the LLM at all. Only the LLM-scored `risk_threshold` gate is
affected by model choice.

---

## Policy configuration

Policy is YAML, loaded from `policies/default.yaml`, hot-reloadable without a restart. It combines
deterministic rules (tool allow/deny lists, file-path and domain patterns, a content-aware
destructive-shell-command screen, session limits) with the LLM-scored risk threshold — illustrative
subset below, see the shipped file for the full rule set and rationale:

```yaml
policy:
  name: default
  risk_threshold: 0.75        # risk score at or above this → BLOCK
  review_threshold: 0.60      # between this and risk_threshold → REVIEW

  deny_tools: []               # categorical tool bans by name, if you want one (empty by default)

  shell_command_policy:        # content-aware screen for shell/bash actions — inspects the
    enabled: true               # command itself, not just the tool name

  deny_path_patterns:          # file path globs, always blocked
    - ~/.ssh/**
    - ~/.aws/credentials
    - "**/*.pem"
    - "**/*.key"

  deny_domains:                # outbound HTTP domains, always blocked
    - "*.ngrok.io"
    - "*.requestbin.com"
    - webhook.site

  review_tools:                # flagged for human review, not auto-blocked
    - email.send
    - git.push
    - file.write

  session_limits:
    max_actions: 5000
    max_blocked: 10             # session gets stricter thresholds after this many blocks
```

Hot-reload without restarting:

```bash
curl -X POST http://localhost:8747/api/v1/policies/reload
```

---

## Running tests

No API key required — the test suite mocks the LLM.

```bash
pytest tests/ -v
# 586 passed
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
tests/              586 tests
examples/           demo_attack.py, openai_agent_example.py,
                    langgraph_agent_example.py, openclaw_agent_example.py,
                    openclaw_skill.ts
```

---

## License

MIT
