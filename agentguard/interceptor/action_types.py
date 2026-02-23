"""ActionType inference and credential path patterns."""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from agentguard.core.models import ActionType

# Credential and sensitive path patterns — always triggers CREDENTIAL_ACCESS
CREDENTIAL_PATTERNS: list[str] = [
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".ssh/id_ecdsa",
    ".ssh/id_dsa",
    ".ssh/authorized_keys",
    ".ssh/known_hosts",
    ".aws/credentials",
    ".aws/config",
    ".env",
    ".netrc",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "credentials.json",
]

CREDENTIAL_EXTENSIONS: set[str] = {".pem", ".key", ".p12", ".pfx", ".crt", ".cer"}

# Tool name patterns → ActionType mapping
_TOOL_TYPE_PATTERNS: list[tuple[re.Pattern[str], ActionType]] = [
    (re.compile(r"^(bash|shell|subprocess|exec|run_command|terminal|sh)\b", re.I), ActionType.SHELL_COMMAND),
    (re.compile(r"^(file\.write|write_file|save_file|create_file|append_file)\b", re.I), ActionType.FILE_WRITE),
    (re.compile(r"^(file\.read|read_file|open_file|cat|read)\b", re.I), ActionType.FILE_READ),
    (re.compile(r"^(http|requests?|curl|fetch|web_request|http_request|http_post|http_get)\b", re.I), ActionType.HTTP_REQUEST),
    (re.compile(r"^(memory\.(write|set|update)|set_memory|update_memory)\b", re.I), ActionType.MEMORY_WRITE),
    (re.compile(r"^(credential|secret|vault|keychain)\b", re.I), ActionType.CREDENTIAL_ACCESS),
]


def _normalize_path(path: str) -> str:
    """Normalize path: expand ~, resolve to forward slashes, lowercase."""
    expanded = os.path.expanduser(path)
    return expanded.replace("\\", "/")


def is_credential_path(path: str) -> bool:
    """
    Return True if path matches any known credential pattern.

    Uses suffix matching against known sensitive filenames and directories,
    plus extension matching for certificate/key files.
    """
    normalized = _normalize_path(path).lower()
    p = PurePosixPath(normalized)

    # Check file extension
    if p.suffix in CREDENTIAL_EXTENSIONS:
        return True

    # Check for known credential filenames/paths by suffix matching
    for pattern in CREDENTIAL_PATTERNS:
        pattern_lower = pattern.lower()
        # Match if the normalized path ends with the pattern (handles ~ expansion)
        if normalized.endswith("/" + pattern_lower) or normalized == pattern_lower:
            return True
        # Also match basename for simple filename patterns (no slashes)
        if "/" not in pattern_lower and p.name == pattern_lower:
            return True

    # Catch bare .env files (starts with dot — fnmatch "*.env" misses these)
    if p.name == ".env" or p.name.endswith(".env"):
        return True

    return False


def infer_action_type(tool_name: str, parameters: dict) -> ActionType:
    """Infer the ActionType from tool name and parameters."""
    # Check tool name against patterns — write before read so write tools classified correctly
    for pattern, action_type in _TOOL_TYPE_PATTERNS:
        if pattern.match(tool_name):
            # Override write to CREDENTIAL_ACCESS if credential path
            if action_type == ActionType.FILE_WRITE:
                path = extract_file_path(parameters)
                if path and is_credential_path(path):
                    return ActionType.CREDENTIAL_ACCESS
            return action_type

    # Inspect parameters for file paths
    path = extract_file_path(parameters)
    if path:
        if is_credential_path(path):
            return ActionType.CREDENTIAL_ACCESS
        # Distinguish write vs read by tool name keywords
        if any(kw in tool_name.lower() for kw in ("write", "save", "create", "append", "put")):
            return ActionType.FILE_WRITE
        return ActionType.FILE_READ

    # Inspect parameters for URLs
    if extract_url_domain(parameters) is not None:
        return ActionType.HTTP_REQUEST

    # Inspect for shell commands
    cmd_keys = ("command", "cmd", "script")
    for key in cmd_keys:
        if parameters.get(key):
            return ActionType.SHELL_COMMAND

    return ActionType.TOOL_CALL


def extract_url_domain(parameters: dict) -> str | None:
    """
    Extract domain from URL-like parameters.

    Returns hostname only (no port), suitable for domain matching.
    """
    url_keys = ("url", "endpoint", "uri", "href")
    for key in url_keys:
        if val := parameters.get(key):
            if isinstance(val, str):
                try:
                    url = val if "://" in val else f"https://{val}"
                    parsed = urlparse(url)
                    # Use .hostname (not .netloc) to strip port number
                    return parsed.hostname or None
                except Exception:
                    pass
    return None


def extract_file_path(parameters: dict) -> str | None:
    """Extract file path from parameters."""
    path_keys = ("path", "file", "filename", "filepath", "file_path")
    for key in path_keys:
        if val := parameters.get(key):
            if isinstance(val, str):
                return val
    return None
