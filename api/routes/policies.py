"""Policy management API endpoints."""

from __future__ import annotations

import os
from typing import Any

import yaml
from fastapi import APIRouter, HTTPException

from agentguard.policy.schema import PolicyConfig
from api.dependencies import PolicyDep

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])


@router.get("", response_model=dict)
async def get_active_policy(engine: PolicyDep) -> dict:
    """Get the currently active policy configuration."""
    config = engine.config
    return config.model_dump()


@router.post("/validate")
async def validate_policy(body: dict[str, Any]) -> dict:
    """Validate a policy YAML structure without applying it."""
    try:
        yaml_str = body.get("yaml", "")
        data = yaml.safe_load(yaml_str)
        policy_data = data.get("policy", data)
        config = PolicyConfig(**policy_data)
        return {
            "valid": True,
            "policy_name": config.name,
            "risk_threshold": config.risk_threshold,
            "deny_tools_count": len(config.deny_tools),
            "deny_domains_count": len(config.deny_domains),
        }
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/raw")
async def get_raw_policy(engine: PolicyDep) -> dict:
    """Return the raw YAML text of the active policy file."""
    path = getattr(engine, "_path", None)
    if not path or not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Policy file not found on disk")
    with open(path) as f:
        return {"yaml": f.read(), "path": path}


@router.post("/save")
async def save_policy(body: dict[str, Any], engine: PolicyDep) -> dict:
    """Validate, write to disk, and hot-reload the policy."""
    yaml_str = body.get("yaml", "")
    try:
        data = yaml.safe_load(yaml_str)
        policy_data = data.get("policy", data)
        PolicyConfig(**policy_data)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    path = getattr(engine, "_path", None)
    if not path:
        raise HTTPException(status_code=400, detail="No policy file path configured")
    with open(path, "w") as f:
        f.write(yaml_str)
    engine.reload()
    return {"saved": True, "policy_name": engine.config.name}


@router.post("/reload")
async def reload_policy(engine: PolicyDep) -> dict:
    """Hot-reload the active policy from disk."""
    try:
        engine.reload()
        return {"reloaded": True, "policy_name": engine.config.name}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Reload failed: {exc}")
