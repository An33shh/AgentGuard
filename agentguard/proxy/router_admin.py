"""
Proxy admin endpoints — session introspection and recovery.

session_limits.max_blocked has no time window or decay: once a session's
blocked count reaches it, every subsequent action for that session_id is
blocked forever, with no automatic recovery, and the counters live only in
this process's memory (invisible to the dashboard, which talks to a separate
API process). These endpoints are the operator-visible way to see and clear
that state without restarting the whole proxy — see project memory: the
2026-08-11 dogfood incident, where a demoted/locked-out session had no
visible cause or recovery path short of a full process restart.

Gated behind verify_proxy_admin_auth (same AGENTGUARD_API_KEY/JWT posture as
the main API — auth is required only when those are configured, matching
this proxy's existing "auth optional" posture everywhere else). A pentest
found these endpoints reachable by any network client with zero
authentication, letting anyone reset any session's lockout state on demand.
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from agentguard.proxy.dependencies import get_proxy_interceptor, verify_proxy_admin_auth

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(verify_proxy_admin_auth)])


@router.get("/sessions/{session_id}")
async def get_session(session_id: str) -> JSONResponse:
    interceptor = get_proxy_interceptor()
    return JSONResponse(interceptor.get_session_stats(session_id))


@router.post("/sessions/{session_id}/reset")
async def reset_session(session_id: str) -> JSONResponse:
    interceptor = get_proxy_interceptor()
    existed = await interceptor.reset_session(session_id)
    if not existed:
        raise HTTPException(status_code=404, detail=f"No recorded state for session_id={session_id!r}")
    logger.info("proxy_admin_session_reset", session_id=session_id)
    return JSONResponse({"session_id": session_id, "reset": True})
