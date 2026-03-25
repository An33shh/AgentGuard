"""AgentGuard FastAPI application."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from dotenv import load_dotenv

# Load environment-specific defaults first (.env.dev / .env.production),
# then let .env (gitignored, machine-local secrets) override individual values.
_env_name = os.getenv("ENV", "development")
_repo_root = Path(__file__).parent.parent
load_dotenv(_repo_root / f".env.{_env_name}", override=False)
load_dotenv(_repo_root / ".env", override=True)

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from agentguard.auth.jwt_utils import auth_enabled, validate_auth_config
from agentguard.telemetry.logger import configure_logging
from api.dependencies import check_rate_limit, verify_auth
from api.middleware.request_id import RequestIDMiddleware
from api.routes import agents, auth, demo, events, health, insights, intercept, policies


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    log_level = os.getenv("AGENTGUARD_LOG_LEVEL", "INFO")
    configure_logging(
        log_level=log_level,
        json_logs=os.getenv("AGENTGUARD_JSON_LOGS", "true").lower() == "true",
    )
    import structlog
    logger = structlog.get_logger(__name__)

    # Fail fast on misconfigured auth before accepting any traffic
    validate_auth_config()

    # Eagerly initialise the policy engine and interceptor so any misconfiguration
    # (missing YAML, bad env vars, unreachable backend) surfaces at startup rather
    # than on the first request. Both are @lru_cache singletons — this call primes
    # the cache; subsequent calls return the same object at O(1).
    from api.dependencies import get_interceptor, get_ledger, get_policy_engine
    from agentguard.ledger.db import PostgresEventLedger
    try:
        get_policy_engine()
        interceptor = get_interceptor()
        ledger = get_ledger()
    except Exception as exc:
        logger.critical("startup_dependency_failed", error=str(exc), exc_info=True)
        raise SystemExit(1) from exc

    # Auto-create tables for SQLite local dev (no Alembic needed)
    if isinstance(ledger, PostgresEventLedger) and ledger._is_sqlite:
        await ledger.create_tables()
        logger.info("sqlite_tables_created")

    # Auto-seed demo scenarios so the dashboard has data on first run
    if os.getenv("AGENTGUARD_AUTO_SEED", "").lower() == "true":
        from api.routes.demo import OPENCLAW_SCENARIOS
        import uuid as _uuid
        existing = await ledger.list_events(limit=1)
        if not existing:
            # Attack scenarios in one session — triggers realistic demotion
            attack_session = f"openclaw-demo-{_uuid.uuid4().hex[:8]}"
            # Baseline legitimate scenario in its own session to avoid demotion interference
            baseline_session = f"openclaw-baseline-{_uuid.uuid4().hex[:8]}"
            for scenario in OPENCLAW_SCENARIOS:
                sid = baseline_session if scenario.get("description", "").startswith("Legitimate") else attack_session
                await interceptor.intercept(
                    raw_payload=scenario["payload"],
                    agent_goal=scenario["goal"],
                    session_id=sid,
                    framework="demo",
                )
            logger.info("demo_scenarios_seeded", attack_session=attack_session, baseline_session=baseline_session)

    logger.info(
        "agentguard_api_starting",
        version="0.6.0",
        auth_enabled=auth_enabled(),
    )
    yield
    logger.info("agentguard_api_stopping")


def create_app() -> FastAPI:
    # Routes under /api/v1/* require auth + rate limiting when auth is enabled
    protected_deps = [Depends(verify_auth), Depends(check_rate_limit)]

    app = FastAPI(
        title="AgentGuard API",
        description="Runtime detection and response platform for AI agents",
        version="0.5.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # Request ID middleware — must be added before CORS so the ID is set early
    app.add_middleware(RequestIDMiddleware)

    # CORS
    cors_origins = [
        o.strip()
        for o in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
        if o.strip()
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request, exc: HTTPException):
        if isinstance(exc.detail, dict) and "error_code" in exc.detail:
            content = exc.detail
        elif isinstance(exc.detail, str):
            content = {"error_code": "INTERNAL_ERROR", "message": exc.detail}
        else:
            content = {"error_code": "INTERNAL_ERROR", "message": str(exc.detail)}
        return JSONResponse(
            status_code=exc.status_code,
            content=content,
            headers=dict(exc.headers or {}),
        )

    # Public routes (no auth)
    app.include_router(health.router)
    app.include_router(auth.router)

    # Protected routes — auth + rate limit applied globally per-router
    app.include_router(events.router, dependencies=protected_deps)
    app.include_router(policies.router, dependencies=protected_deps)
    app.include_router(insights.router, dependencies=protected_deps)
    app.include_router(agents.router, dependencies=protected_deps)
    app.include_router(demo.router, dependencies=protected_deps)
    app.include_router(intercept.router, dependencies=protected_deps)

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api.main:app",
        host=os.getenv("API_HOST", "0.0.0.0"),
        port=int(os.getenv("API_PORT", "8747")),
        reload=os.getenv("AGENTGUARD_DEV_RELOAD", "false").lower() == "true",
    )
