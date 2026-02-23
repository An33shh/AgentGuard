"""AgentGuard FastAPI application."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from agentguard.telemetry.logger import configure_logging
from api.routes import agents, demo, events, health, insights, policies


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan — startup and shutdown."""
    log_level = os.getenv("AGENTGUARD_LOG_LEVEL", "INFO")
    configure_logging(log_level=log_level, json_logs=os.getenv("AGENTGUARD_JSON_LOGS", "true").lower() == "true")

    import structlog
    logger = structlog.get_logger(__name__)
    logger.info("agentguard_api_starting", version="0.1.0")

    yield

    logger.info("agentguard_api_stopping")


def create_app() -> FastAPI:
    app = FastAPI(
        title="AgentGuard API",
        description="Runtime detection and response platform for AI agents",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # CORS
    cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register routes
    app.include_router(health.router)
    app.include_router(events.router)
    app.include_router(policies.router)
    app.include_router(insights.router)
    app.include_router(agents.router)
    app.include_router(demo.router)

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api.main:app",
        host=os.getenv("API_HOST", "0.0.0.0"),
        port=int(os.getenv("API_PORT", "8000")),
        reload=os.getenv("AGENTGUARD_DEV_RELOAD", "false").lower() == "true",
    )
