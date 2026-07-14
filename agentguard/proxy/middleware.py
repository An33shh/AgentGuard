"""
Proxy middleware: FailClosedMiddleware and RequestIDMiddleware.
"""

from __future__ import annotations

import uuid
from typing import Any

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = structlog.get_logger(__name__)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Attach a unique X-Request-ID header to every request/response."""

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        # Store on request state for downstream handlers
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


class FailClosedMiddleware(BaseHTTPMiddleware):
    """
    Catch all unhandled exceptions and return a 500 blocked response.

    In proxy mode, *never* allow a request to pass through when the
    security pipeline has crashed — that would defeat the purpose of
    the proxy.
    """

    def __init__(self, app: Any, fail_closed: bool = True) -> None:
        super().__init__(app)
        self._fail_closed = fail_closed

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        try:
            return await call_next(request)
        except Exception as exc:
            request_id = getattr(request.state, "request_id", "unknown")
            logger.error(
                "proxy_unhandled_exception",
                path=request.url.path,
                request_id=request_id,
                error=str(exc),
                exc_info=True,
            )
            if self._fail_closed:
                return JSONResponse(
                    status_code=500,
                    content={
                        "error": {
                            "message": (
                                "[AgentGuard] Request blocked due to an internal proxy error. "
                                "This is a fail-closed safety response."
                            ),
                            "type": "proxy_error",
                            "code": "agentguard_fail_closed",
                            "request_id": request_id,
                        }
                    },
                )
            raise
