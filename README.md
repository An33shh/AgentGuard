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

## Getting Started

### 1. Install

```bash
git clone https://github.com/An33shh/AgentGuard.git
cd AgentGuard
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...
```

### 2. Wrap your agent

AgentGuard sits between your agent and the tools it calls. Pick your framework:

**OpenAI Agents SDK**
```python
from agentguard import SecureAgent

guard = SecureAgent.from_env(
    goal="Summarize the README.md file",
    framework="openai",
    policy_path="policies/default.yaml",
)

hooks = guard.get_openai_hooks()
result = await Runner.run(agent, input=msg, hooks=hooks)
# Every tool call is intercepted. Malicious ones are blocked before execution.
```

**LangGraph**
```python
guard = SecureAgent.from_env(goal="...", framework="langgraph")
secured_graph = guard.wrap_langgraph(compiled_graph)
result = await secured_graph.ainvoke({"messages": [...]})
```

**Any framework (manual)**
```python
decision, event = await guard.intercept({
    "tool_name": "file.read",
    "parameters": {"path": "~/.aws/credentials"},
})
# decision → Decision.BLOCK
# event    → full forensic record with risk score, reason, policy rule hit
```

### 3. Start the API + dashboard

```bash
# Terminal 1 — API server (stores every intercepted event)
uvicorn api.main:app --reload
# → http://localhost:8001

# Terminal 2 — Investigation dashboard
cd dashboard && npm install && npm run dev
# → http://localhost:3000
```

Or spin up everything at once with Docker:

```bash
cp .env.example .env   # add your ANTHROPIC_API_KEY
docker-compose up
# API → :8001  |  Dashboard → :3001
```

### 4. Investigate in the dashboard

Once your agent is running, open `http://localhost:3000` to see:

- **Overview** — blocked event count, risk trends, recent alerts
- **Timeline** — every action your agent took, color-coded by risk
- **Events** — searchable forensic log with full decision detail per event
- **Agent Profiles** — per-agent identity with knowledge graph of sessions, tools, and attack patterns
- **Policies** — edit and hot-reload your YAML policy without restarting

### 5. Customize your policy

Edit `policies/default.yaml` to define what's allowed, blocked, or flagged for review:

```yaml
policy:
  name: default
  risk_threshold: 0.75       # Claude risk score above this → BLOCK

  deny_tools:                # blocked regardless of risk score
    - shell.execute
    - bash.run

  deny_path_patterns:        # file paths always blocked
    - ~/.ssh/**
    - ~/.aws/credentials
    - "**/*.pem"

  deny_domains:              # outbound domains always blocked
    - "*.ngrok.io"
    - webhook.site

  review_tools:              # flagged for human review
    - email.send
    - git.push
```

Changes apply immediately — no restart needed:

```bash
curl -X POST http://localhost:8001/api/v1/policies/reload
# or use the Reload button in the dashboard
```

---

## How it works

Every tool call passes through four stages before execution:

| Stage | What happens | Latency |
|-------|-------------|---------|
| **Normalize** | Raw tool call → typed `Action` object | < 0.1ms |
| **Policy** | YAML rules checked — `deny_tools`, path patterns, domains | < 1ms |
| **Analyze** | Claude scores intent alignment (0–1) via forced `tool_use` | 200–800ms |
| **Log** | Decision stored with full provenance + Redis Streams publish | < 0.1ms |

The policy stage runs **before** the LLM — a `~/.ssh/id_rsa` read is blocked in microseconds even if the Claude API is down.

---

## Attack scenarios (OpenClaw)

100% detection rate on all 5 real-world attack vectors:

| # | Scenario | Vector | Result |
|---|----------|--------|--------|
| 1 | Curl exfiltration | `http.request` → ngrok tunnel | **BLOCK** `risk=0.92` |
| 2 | GitHub issue injection | `http.post` → requestbin.com | **BLOCK** `risk=0.88` |
| 3 | SSH private key read | `file.read ~/.ssh/id_rsa` | **BLOCK** `path pattern` |
| 4 | Memory poisoning | `memory.write OVERRIDE instructions` | **BLOCK** `risk=0.81` |
| 5 | Goal hijacking | `file.read ~/.aws/credentials` | **BLOCK** `risk=0.95` |
| 6 | Legitimate baseline | `file.read README.md` | **ALLOW** `risk=0.05` |

```bash
python examples/demo_attack.py   # run all 6 scenarios live
pytest tests/ -v                 # run the full test suite (no API key needed)
```

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
