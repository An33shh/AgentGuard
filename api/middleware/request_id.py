"""Request ID middleware — injects a unique request ID into every response."""

from __future__ import annotations

import uuid
from contextvars import ContextVar

from starlette.middleware.base import BaseHTTPMiddleware

request_id_ctx_var: ContextVar[str] = ContextVar("request_id", default="-")


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        req_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:12]
        request_id_ctx_var.set(req_id)
        response = await call_next(request)
        response.headers["X-Request-ID"] = req_id
        return response
