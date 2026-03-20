# agentguard_rs — Native Rust Policy Matcher

Optional Rust extension for AgentGuard. When compiled and installed, the policy engine
uses this for pattern matching (~5-10µs) instead of Python compiled regexes (~50µs).

Falls back silently to Python if not installed — no configuration needed.

## Build

Requires Rust (https://rustup.rs) and maturin:

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install maturin into the active venv
pip install maturin

# Compile and install into the active venv
cd agentguard_rs
maturin develop --release
```

## Verify

```python
from agentguard.policy._native import RUST_AVAILABLE
print(RUST_AVAILABLE)  # True when compiled

from agentguard.policy.engine import PolicyEngine
from agentguard.policy.schema import PolicyConfig
e = PolicyEngine(config=PolicyConfig.from_yaml("policies/default.yaml"))
print(e._native)  # <PolicyMatcher object> when Rust active
```

## What it accelerates

Pattern matching in `PolicyEngine.evaluate()`, `evaluate_abac()`, and `evaluate_provenance()`:

| Operation         | Python (pre-compiled regex) | Rust (DFA)  |
|-------------------|-----------------------------|-------------|
| deny_tools check  | ~5-20µs                     | ~0.5-2µs   |
| path glob match   | ~10-30µs                    | ~1-3µs     |
| domain match      | ~5-15µs                     | ~0.5-1µs   |
| full evaluate()   | ~50µs                       | ~5-10µs    |

The LLM intent analysis (200-800ms) dominates total latency. The Rust matcher matters
at very high throughput where thousands of policy-only blocks occur per second.

## Safety

- All regex matching uses the `regex` crate (DFA, O(n) — no catastrophic backtracking)
- Paths >4096 bytes are rejected without matching (DoS guard)
- Construction errors fall back to Python silently
