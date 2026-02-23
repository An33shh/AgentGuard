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

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-73%20passing-22c55e?style=flat-square&logo=pytest&logoColor=white)](#)
[![Next.js](https://img.shields.io/badge/Next.js-15-black?style=flat-square&logo=next.js&logoColor=white)](https://nextjs.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-6366f1?style=flat-square)](#license)

</div>

---

## Overview

AgentGuard intercepts every tool call an AI agent makes **before** it executes — analyzing intent, enforcing policies, and logging a forensic timeline. Built in response to the OpenClaw security incidents (Jan–Feb 2026) that exposed the complete absence of runtime security tooling for autonomous agents.

```
USER → AI AGENT → AgentGuard (Middleware) → Tools / APIs / System
         ↑               ↓
         └──── BLOCK ─────┘
```

---

## Quick Start

```bash
# Install
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...

# Run the attack demo
python examples/demo_attack.py

# Run tests (no API key needed)
pytest tests/ -v

# Start API
uvicorn api.main:app --reload

# Start dashboard
cd dashboard && npm install && npm run dev
```

Or with Docker:

```bash
cp .env.example .env   # add your API key
docker-compose up
# API → :8001  |  Dashboard → :3001
```

---

## Detection Pipeline

Every action passes through four stages in sequence:

| Stage | Description | Latency |
|-------|-------------|---------|
| **Normalize** | Convert raw tool calls to typed `Action` objects | < 0.1ms |
| **Policy** | Deterministic YAML rules — `deny_tools`, `deny_path_patterns`, `deny_domains` | < 1ms |
| **Analyze** | Claude intent scoring via forced `tool_use` (structured JSON output) | 200–800ms |
| **Log** | Forensic event stored with full provenance + Redis Streams publish | < 0.1ms |

The policy stage runs **before** the LLM. A `~/.ssh/id_rsa` read is blocked in microseconds even if the Claude API is down.

---

## OpenClaw Attack Scenarios

All 5 real-world attack vectors from the OpenClaw incidents — 100% detection rate.

| # | Scenario | Vector | Result |
|---|----------|--------|--------|
| 1 | Curl exfiltration | `http.request` → ngrok tunnel | **BLOCK** `risk=0.92` |
| 2 | GitHub issue injection | `http.post` → requestbin.com | **BLOCK** `risk=0.88` |
| 3 | SSH private key read | `file.read ~/.ssh/id_rsa` | **BLOCK** `path pattern` |
| 4 | Memory poisoning | `memory.write OVERRIDE instructions` | **BLOCK** `risk=0.81` |
| 5 | Goal hijacking | `file.read ~/.aws/credentials` | **BLOCK** `risk=0.95` |
| 6 | Legitimate baseline | `file.read README.md` | **ALLOW** `risk=0.05` |

---

## Usage

### SecureAgent Facade

```python
from agentguard import SecureAgent

guard = SecureAgent.from_env(
    goal="Summarize the README.md file",
    framework="openai",
    policy_path="policies/default.yaml",
)

decision, event = await guard.intercept({
    "tool_name": "file.read",
    "parameters": {"path": "~/.aws/credentials"},
})
# → Decision.BLOCK  risk_score=0.95
```

### OpenAI Agents SDK

```python
hooks = guard.get_openai_hooks()
result = await Runner.run(agent, input=msg, hooks=hooks)
```

### LangGraph

```python
secured_graph = guard.wrap_langgraph(compiled_graph)
result = await secured_graph.ainvoke({"messages": [...]})
```

---

## Policy Configuration

```yaml
# policies/default.yaml
policy:
  name: default
  risk_threshold: 0.75

  deny_tools:
    - shell.execute
    - bash.run

  deny_path_patterns:
    - ~/.ssh/**
    - ~/.aws/credentials
    - "**/*.pem"
    - "**/*.key"

  deny_domains:
    - "*.ngrok.io"
    - "*.requestbin.com"
    - webhook.site

  review_tools:
    - email.send
    - file.write
    - git.push
```

Policies hot-reload without restarting the server:

```bash
curl -X POST http://localhost:8001/api/v1/policies/reload
```

---

## Dashboard

Next.js 15 investigation interface with:

- **Overview** — live stat cards, risk sparkline, recent blocked feed
- **Timeline** — session-based attack timeline with risk trend
- **Events** — filterable event table with forensic detail view
- **Agent Profiles** — persistent identity profiles with force-directed knowledge graphs
- **Policies** — live YAML viewer with hot-reload

---

## Architecture

```
agentguard/
├── core/           # Pydantic models, SecureAgent facade
├── interceptor/    # Normalization + interception pipeline
├── analyzer/       # Claude intent analysis (forced tool_use)
├── policy/         # Deterministic YAML rule engine
├── ledger/         # InMemory + PostgreSQL/pgvector event storage
├── telemetry/      # OpenTelemetry + structlog
├── adapters/       # OpenAI Agents SDK + LangGraph middleware
└── integrations/   # Redis Streams, enrichment, insights

api/                # FastAPI: /events, /agents, /timeline, /policies
dashboard/          # Next.js 15 App Router
policies/           # default.yaml + strict.yaml
tests/              # 73 tests — 6 OpenClaw scenarios + unit suite
```

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Python 3.12, FastAPI, SQLAlchemy (async), Alembic |
| Risk Engine | Anthropic Claude Sonnet 4.6 — forced `tool_use` |
| Database | PostgreSQL 16 + pgvector |
| Event Bus | Redis Streams |
| Frontend | Next.js 15, React 19, Tailwind CSS, Recharts |
| Adapters | OpenAI Agents SDK, LangGraph |
| Observability | OpenTelemetry, structlog |
| Infra | Docker Compose |

---

## License

MIT — see [LICENSE](LICENSE).
