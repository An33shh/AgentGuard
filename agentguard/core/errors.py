"""Structured error catalog for AgentGuard API."""

from __future__ import annotations

from enum import Enum

from fastapi import HTTPException


class ErrorCode(str, Enum):
    AUTH_TOKEN_REQUIRED  = "AUTH_TOKEN_REQUIRED"
    AUTH_TOKEN_EXPIRED   = "AUTH_TOKEN_EXPIRED"
    AUTH_TOKEN_INVALID   = "AUTH_TOKEN_INVALID"
    AUTH_TOKEN_REVOKED   = "AUTH_TOKEN_REVOKED"
    AUTH_BAD_CREDENTIALS = "AUTH_BAD_CREDENTIALS"
    RATE_LIMIT_EXCEEDED  = "RATE_LIMIT_EXCEEDED"
    NOT_FOUND            = "NOT_FOUND"
    VALIDATION_ERROR     = "VALIDATION_ERROR"
    POLICY_INVALID       = "POLICY_INVALID"
    INTERNAL_ERROR       = "INTERNAL_ERROR"


class AgentGuardHTTPError(HTTPException):
    """HTTPException with a structured error_code field."""

    def __init__(
        self,
        status_code: int,
        error_code: ErrorCode,
        message: str,
        headers: dict | None = None,
    ) -> None:
        super().__init__(
            status_code=status_code,
            detail={"error_code": error_code.value, "message": message},
            headers=headers,
        )
