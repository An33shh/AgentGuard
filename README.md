# AgentGuard

**Runtime detection and response platform for AI agents.**

> CrowdStrike for AI agents. Not a prompt filter — secures autonomous decisions at runtime.

Built in response to the OpenClaw security incidents (Jan–Feb 2026) that exposed the complete absence of runtime security tooling for autonomous agents.

```
USER → AI AGENT → AgentGuard (Middleware) → Tools / APIs / System
```

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Set your API key
export ANTHROPIC_API_KEY=sk-ant-...

# Run the OpenClaw attack demo
python examples/demo_attack.py

# Run tests (no API key needed — uses mock analyzer)
pytest tests/ -v

# Start the API server
uvicorn api.main:app --reload

# Start the dashboard
cd dashboard && npm install && npm run dev
```

---

## Architecture

```
agentguard/
├── core/           # Pydantic models, SecureAgent facade, exceptions
├── interceptor/    # Action normalization + interception pipeline
├── analyzer/       # Claude claude-sonnet-4-6 forced tool_use intent analysis
├── policy/         # Deterministic YAML rule evaluation (zero-latency)
├── ledger/         # InMemory (Phase 1) + Postgres+pgvector (Phase 2)
├── telemetry/      # OpenTelemetry + structlog
└── adapters/       # OpenAI Agents SDK + LangGraph middleware
api/                # FastAPI: /events, /timeline, /policies, /health
dashboard/          # Next.js 15: Dashboard, Timeline, Events, Policies
policies/           # default.yaml + strict.yaml
tests/              # pytest: 6 OpenClaw scenarios + unit tests
```

---

## OpenClaw Attack Scenarios

| # | Scenario | Expected |
|---|----------|----------|
| 1 | Curl exfiltration → ngrok tunnel | **BLOCK** |
| 2 | GitHub issue injection → requestbin | **BLOCK** |
| 3 | SSH private key read | **BLOCK** |
| 4 | Memory poisoning (OVERRIDE instructions) | **BLOCK** |
| 5 | Goal hijacking → AWS credential theft | **BLOCK** |
| 6 | Legitimate README read (baseline) | **ALLOW** |

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
# → Decision.BLOCK, risk_score=0.95
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

## Detection Pipeline

1. **Normalize** — Convert raw tool calls to typed `Action` objects
2. **Policy check** — Deterministic YAML rules (zero-latency, runs before LLM)
   - `deny_tools` → instant BLOCK
   - `deny_path_patterns` → instant BLOCK (fnmatch)
   - `deny_domains` → instant BLOCK (domain matching)
3. **Intent analysis** — Claude claude-sonnet-4-6 with forced `tool_use` output
4. **Risk threshold** — BLOCK if `risk_score >= 0.75` (configurable)
5. **Log** — Forensic event stored in ledger with full provenance

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.12, FastAPI, uvicorn |
| Risk Engine | Anthropic Claude claude-sonnet-4-6 (forced tool_use) |
| Database | Postgres 16 + pgvector |
| Frontend | Next.js 15, Tailwind CSS, Recharts |
| Testing | pytest, pytest-asyncio |

---