"""Policy management API endpoints."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
import pydantic
from fastapi import APIRouter

from agentguard.core.errors import AgentGuardHTTPError, ErrorCode
from agentguard.policy.schema import PolicyConfig
from api.dependencies import PolicyDep

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])

# Allowed base directory for policy files — prevents path traversal
_POLICY_BASE_DIR = Path(os.getenv("AGENTGUARD_POLICY_DIR", "policies")).resolve()


def _safe_policy_path(path: str | None) -> Path:
    """Resolve policy path and assert it stays within the allowed directory."""
    if not path:
        raise AgentGuardHTTPError(400, ErrorCode.VALIDATION_ERROR, "No policy file path configured")
    resolved = Path(path).resolve()
    try:
        resolved.relative_to(_POLICY_BASE_DIR)
    except ValueError:
        raise AgentGuardHTTPError(403, ErrorCode.VALIDATION_ERROR, "Policy file path is outside the allowed directory")
    return resolved


@router.get("", response_model=dict)
async def get_active_policy(engine: PolicyDep) -> dict:
    """Get the currently active policy configuration."""
    return engine.config.model_dump()


@router.post("/validate")
async def validate_policy(body: dict[str, Any]) -> dict:
    """Validate a policy YAML structure without applying it."""
    yaml_str = body.get("yaml", "")
    try:
        data = yaml.safe_load(yaml_str)
    except yaml.YAMLError:
        raise AgentGuardHTTPError(422, ErrorCode.VALIDATION_ERROR, "Invalid YAML syntax")
    if not isinstance(data, dict):
        raise AgentGuardHTTPError(422, ErrorCode.VALIDATION_ERROR, "Policy must be a YAML mapping")
    policy_data = data.get("policy", data)
    try:
        config = PolicyConfig(**policy_data)
    except pydantic.ValidationError as exc:
        # Surface field-level validation errors without leaking internal paths
        raise AgentGuardHTTPError(
            422,
            ErrorCode.POLICY_INVALID,
            f"Policy validation failed: {exc.errors()}",
        )
    return {
        "valid": True,
        "policy_name": config.name,
        "risk_threshold": config.risk_threshold,
        "deny_tools_count": len(config.deny_tools),
        "deny_domains_count": len(config.deny_domains),
    }


@router.get("/raw")
async def get_raw_policy(engine: PolicyDep) -> dict:
    """Return the raw YAML text of the active policy file."""
    path = _safe_policy_path(getattr(engine, "_path", None))
    if not path.exists():
        raise AgentGuardHTTPError(404, ErrorCode.NOT_FOUND, "Policy file not found on disk")
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        raise AgentGuardHTTPError(500, ErrorCode.INTERNAL_ERROR, "Failed to read policy file")
    return {"yaml": content, "path": str(path)}


@router.post("/save")
async def save_policy(body: dict[str, Any], engine: PolicyDep) -> dict:
    """Validate, write to disk, and hot-reload the policy."""
    yaml_str = body.get("yaml", "")
    try:
        data = yaml.safe_load(yaml_str)
    except yaml.YAMLError:
        raise AgentGuardHTTPError(422, ErrorCode.VALIDATION_ERROR, "Invalid YAML syntax")
    if not isinstance(data, dict):
        raise AgentGuardHTTPError(422, ErrorCode.VALIDATION_ERROR, "Policy must be a YAML mapping")
    policy_data = data.get("policy", data)
    try:
        PolicyConfig(**policy_data)
    except pydantic.ValidationError as exc:
        raise AgentGuardHTTPError(
            422,
            ErrorCode.POLICY_INVALID,
            f"Policy validation failed: {exc.errors()}",
        )

    path = _safe_policy_path(getattr(engine, "_path", None))
    try:
        path.write_text(yaml_str, encoding="utf-8")
    except OSError:
        raise AgentGuardHTTPError(500, ErrorCode.INTERNAL_ERROR, "Failed to write policy file")

    try:
        engine.reload()
    except Exception as exc:
        import structlog
        structlog.get_logger(__name__).error("policy_reload_failed", error=str(exc), exc_info=True)
        raise AgentGuardHTTPError(500, ErrorCode.INTERNAL_ERROR, "Policy saved but reload failed — restart the API")

    return {"saved": True, "policy_name": engine.config.name}


@router.post("/reload")
async def reload_policy(engine: PolicyDep) -> dict:
    """Hot-reload the active policy from disk."""
    try:
        engine.reload()
        return {"reloaded": True, "policy_name": engine.config.name}
    except Exception as exc:
        import structlog
        structlog.get_logger(__name__).error("policy_reload_failed", error=str(exc), exc_info=True)
        raise AgentGuardHTTPError(500, ErrorCode.INTERNAL_ERROR, "Policy reload failed")
