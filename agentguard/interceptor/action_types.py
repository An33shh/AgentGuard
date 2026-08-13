"""ActionType inference and credential path patterns."""

from __future__ import annotations

import os
import posixpath
import re
from collections.abc import Iterator
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlparse

from agentguard.core.models import ActionType

# Credential and sensitive path patterns — always triggers CREDENTIAL_ACCESS
CREDENTIAL_PATTERNS: frozenset[str] = frozenset([
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
])

CREDENTIAL_EXTENSIONS: set[str] = {".pem", ".key", ".p12", ".pfx", ".crt", ".cer"}

_SHELL_COMMAND_KEYS: tuple[str, ...] = ("command", "cmd", "script")

# Tool name patterns → ActionType mapping
_TOOL_TYPE_PATTERNS: list[tuple[re.Pattern[str], ActionType]] = [
    (re.compile(r"^(bash|shell|subprocess|exec|run_command|terminal|sh)\b", re.IGNORECASE), ActionType.SHELL_COMMAND),
    (re.compile(r"^(file\.write|write_file|save_file|create_file|append_file)\b", re.IGNORECASE), ActionType.FILE_WRITE),
    (re.compile(r"^(file\.read|read_file|open_file|cat|read)\b", re.IGNORECASE), ActionType.FILE_READ),
    (re.compile(r"^(http|requests?|curl|fetch|web_request|http_request|http_post|http_get)\b", re.IGNORECASE), ActionType.HTTP_REQUEST),
    (re.compile(r"^(memory\.(write|set|update)|set_memory|update_memory)\b", re.IGNORECASE), ActionType.MEMORY_WRITE),
    (re.compile(r"^(credential|secret|vault|keychain)\b", re.IGNORECASE), ActionType.CREDENTIAL_ACCESS),
]


def _normalize_path(path: str) -> str:
    """Normalize path: expand ~, resolve to forward slashes, collapse ../
    traversal segments lexically. A pentest found deny-pattern matching
    trivially defeated by "/tmp/../etc/shadow"-shaped paths when this only
    expanded ~ without resolving ".." — posixpath.normpath (not os.path,
    since paths here are always treated as POSIX-style regardless of host
    OS) collapses that before any pattern comparison happens."""
    expanded = os.path.expanduser(path).replace("\\", "/")
    return posixpath.normpath(expanded)


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
        # Match if the normalized path ends with the pattern (handles ~
        # expansion). lstrip("/") before re-prepending it avoids a
        # double-slash ("//etc/shadow") that a pentest found could never
        # match anything for patterns that already start with "/" (/etc/
        # passwd, /etc/shadow, /etc/sudoers) — those three previously relied
        # entirely on the exact-equality branch below, which "../" traversal
        # trivially defeated before the normpath fix above.
        if normalized == pattern_lower or normalized.endswith("/" + pattern_lower.lstrip("/")):
            return True
        # Also match basename for simple filename patterns (no slashes)
        if "/" not in pattern_lower and p.name == pattern_lower:
            return True

    # Catch bare .env files (starts with dot — fnmatch "*.env" misses these)
    return bool(p.name == ".env" or p.name.endswith(".env"))


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
    for key in _SHELL_COMMAND_KEYS:
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
        if (val := parameters.get(key)) and isinstance(val, str):
            try:
                url = val if "://" in val else f"https://{val}"
                parsed = urlparse(url)
                # Use .hostname (not .netloc) to strip port number
                return parsed.hostname or None
            except Exception:  # noqa: S110 — malformed URL in one param, keep scanning others
                pass
    return None


def extract_file_path(parameters: dict) -> str | None:
    """Extract file path from parameters."""
    path_keys = ("path", "file", "filename", "filepath", "file_path")
    for key in path_keys:
        if (val := parameters.get(key)) and isinstance(val, str):
            return val
    return None


def iter_all_string_values(value: Any) -> Iterator[str]:
    """Recursively yield every string value found anywhere in a (possibly
    nested) parameters structure — dicts, lists, or a bare string.

    Used by the policy engine's content-aware rules (shell_command_policy,
    deny_path_patterns, credential_access, deny_domains) so a dangerous
    value isn't invisible just because a tool schema names its argument
    something other than the conventional command/path/url keys. A pentest
    found the engine's own ActionType classification (which those rules
    used to gate on) trivially defeated this way: a tool call shaped like
    {"tool_name": "run_task", "parameters": {"input": "rm -rf /"}} never
    matches SHELL_COMMAND, so a rule gated on that type never even ran,
    regardless of how dangerous the actual content was.
    """
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from iter_all_string_values(v)
    elif isinstance(value, list):
        for v in value:
            yield from iter_all_string_values(v)


# A conservative "does this look like a URL or bare hostname" filter for
# iter_all_domains — deliberately stricter than extract_url_domain's
# per-key version (which trusts values under url/endpoint/uri/href by
# convention). Scanning *every* string value needs this so ordinary prose
# containing a dot doesn't get mistaken for a domain.
_BARE_HOSTNAME_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)


def _domain_from_string(s: str) -> str | None:
    s = s.strip()
    if not s:
        return None
    if "://" in s:
        candidate = s
    elif _BARE_HOSTNAME_RE.match(s):
        candidate = f"https://{s}"
    else:
        return None
    try:
        return urlparse(candidate).hostname or None
    except Exception:
        return None


def iter_all_domains(parameters: dict) -> Iterator[str]:
    """Yield every URL/hostname-shaped domain found anywhere in parameters
    (recursively), not just under url/endpoint/uri/href keys — see
    iter_all_string_values for why."""
    for val in iter_all_string_values(parameters):
        domain = _domain_from_string(val)
        if domain:
            yield domain


