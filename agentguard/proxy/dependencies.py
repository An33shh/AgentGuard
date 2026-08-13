"""Dependency injection for the LLM API Proxy."""

from __future__ import annotations

import hashlib
import uuid
from functools import lru_cache
from typing import Annotated, Any

import httpx
import structlog
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from agentguard.auth.jwt_utils import auth_enabled, check_token_revocation, verify_token
from agentguard.core.errors import AgentGuardHTTPError, ErrorCode
from agentguard.proxy.config import ProxyConfig
from agentguard.proxy.models import ProxyRequestContext

logger = structlog.get_logger(__name__)

# Cap header-derived values at the same choke point they're first read, to
# the DB columns they'll eventually be written to (agentguard/ledger/db.py's
# EventRecord). Ledger writes are fire-and-forget
# (asyncio.create_task(self._ledger.append(event)) in interceptor.py, no
# error propagation) — an oversized value causes a silent Postgres
# StringDataRightTruncation on PostgresEventLedger, and that failure is
# swallowed: the action is still enforced correctly, but its audit event
# vanishes without a trace. SQLite/InMemory (used in tests) don't enforce
# VARCHAR lengths, so this is invisible without an explicit test.
_MAX_AGENT_ID_LEN = 128         # EventRecord.agent_id
_MAX_FRAMEWORK_LEN = 64         # EventRecord.framework
_MAX_CORRELATION_ID_LEN = 64    # EventRecord.correlation_id
_MAX_GOAL_LEN = 512             # EventRecord.agent_goal is Text (unbounded)
                                 # but capped anyway — defense in depth for
                                 # logs/provenance/enrichment prompt size.

_admin_bearer = HTTPBearer(auto_error=False)


async def verify_proxy_admin_auth(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_admin_bearer)] = None,
) -> None:
    """
    Auth gate for agentguard/proxy/router_admin.py's session-introspection/
    reset endpoints — a pentest found them reachable by any network client
    with zero authentication, letting anyone clear any session's
    session_limits lockout state. Reuses the same AGENTGUARD_API_KEY/
    AGENTGUARD_JWT_SECRET-backed JWT mechanism as api/dependencies.py's
    verify_auth (same "unset both = auth disabled" posture — the rest of
    this proxy has never required auth, and validate_auth_config() at
    startup already guarantees API_KEY/JWT_SECRET are configured
    consistently or not at all), rather than inventing a second auth
    scheme for the proxy's own admin surface.
    """
    if not auth_enabled():
        return

    if credentials is None:
        raise AgentGuardHTTPError(
            status_code=401,
            error_code=ErrorCode.AUTH_TOKEN_REQUIRED,
            message="Bearer token required",
        )

    import jwt as _jwt

    try:
        payload = verify_token(credentials.credentials)
    except _jwt.ExpiredSignatureError:
        raise AgentGuardHTTPError(
            status_code=401,
            error_code=ErrorCode.AUTH_TOKEN_EXPIRED,
            message="Token has expired",
        )
    except _jwt.InvalidTokenError:
        raise AgentGuardHTTPError(
            status_code=401,
            error_code=ErrorCode.AUTH_TOKEN_INVALID,
            message="Invalid token",
        )

    await check_token_revocation(payload)


@lru_cache(maxsize=1)
def get_proxy_config() -> ProxyConfig:
    return ProxyConfig()


@lru_cache(maxsize=1)
def get_http_client() -> httpx.AsyncClient:
    """Shared httpx client for upstream requests. Created once, reused across requests."""
    config = get_proxy_config()
    return httpx.AsyncClient(
        timeout=httpx.Timeout(
            connect=config.upstream_connect_timeout,
            read=config.upstream_read_timeout,
            write=30.0,
            pool=5.0,
        ),
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        follow_redirects=False,
    )


@lru_cache(maxsize=1)
def get_proxy_interceptor() -> Any:
    """Build and cache the AgentGuard Interceptor for proxy use."""
    import os
    from pathlib import Path

    from agentguard.analyzer.backends import create_backend
    from agentguard.analyzer.intent_analyzer import IntentAnalyzer
    from agentguard.interceptor.interceptor import Interceptor
    from agentguard.ledger.event_ledger import EventLedger, InMemoryEventLedger
    from agentguard.policy.engine import PolicyEngine

    config = get_proxy_config()
    _cwd_policy = Path.cwd() / "policies" / "default.yaml"
    _bundled_policy = Path(__file__).parent.parent / "policies" / "default.yaml"
    _default_policy = str(_cwd_policy if _cwd_policy.exists() else _bundled_policy)
    policy_file = str(config.policy_path or os.getenv("AGENTGUARD_POLICY_PATH", _default_policy))

    backend = create_backend()
    hedge_after = float(os.getenv("AGENTGUARD_HEDGE_AFTER", "1.0"))
    analyzer = IntentAnalyzer(backend=backend, hedge_after=hedge_after)
    policy_engine = PolicyEngine.from_yaml(policy_file)

    # Use PostgresEventLedger when DATABASE_URL is configured so proxy events
    # are visible in the dashboard alongside main API events.
    database_url = os.getenv("DATABASE_URL", "")
    ledger: EventLedger
    if database_url:
        from agentguard.ledger.db import PostgresEventLedger
        ledger = PostgresEventLedger(database_url)
    else:
        ledger = InMemoryEventLedger()
        logger.warning(
            "proxy_event_ledger_in_memory",
            detail=(
                "No DATABASE_URL configured — every action this proxy intercepts "
                "will be invisible to the dashboard. Set DATABASE_URL (see .env.dev) "
                "to share storage with the main API."
            ),
        )

    return Interceptor(analyzer=analyzer, policy_engine=policy_engine, event_ledger=ledger)


@lru_cache(maxsize=1)
def get_proxy_guardrail_ledger() -> Any:
    """Persistent GuardrailLedger for the proxy — shares DB with main API when configured."""
    import os
    db_url = os.getenv("AGENTGUARD_GUARDRAIL_DB_URL") or os.getenv("DATABASE_URL", "")
    if db_url:
        from agentguard.guardrail.db import PostgresGuardrailLedger
        return PostgresGuardrailLedger(db_url)
    logger.warning(
        "proxy_guardrail_ledger_in_memory",
        detail=(
            "No DATABASE_URL/AGENTGUARD_GUARDRAIL_DB_URL configured — inbound "
            "guardrail blocks will be invisible to the dashboard."
        ),
    )
    from agentguard.guardrail.ledger import InMemoryGuardrailLedger
    return InMemoryGuardrailLedger()


@lru_cache(maxsize=1)
def get_proxy_guardrail() -> Any | None:
    """Build and cache the PromptGuardrail for proxy use, or None if not configured."""
    config = get_proxy_config()
    if not config.guardrail_mode:
        return None
    from agentguard.guardrail.guardrail import PromptGuardrail
    return PromptGuardrail.from_env(
        mode=config.guardrail_mode,
        deep_analysis=config.guardrail_deep_analysis,
        ledger=get_proxy_guardrail_ledger(),
    )


def proxy_managed_headers(config: ProxyConfig) -> set[str]:
    """
    Lowercased set of AgentGuard-managed request headers that must never be
    forwarded upstream. Derived from live config (not string literals) so a
    deployment that renames a header via an AGENTGUARD_PROXY_*_HEADER env
    var doesn't leak the renamed header verbatim to the real Anthropic/
    OpenAI API.
    """
    return {
        config.goal_header.lower(),
        config.session_header.lower(),
        config.agent_id_header.lower(),
        config.framework_header.lower(),
    }


def build_upstream_headers(request: Request, config: ProxyConfig) -> dict[str, str]:
    """
    Extract headers to forward upstream, removing hop-by-hop and
    AgentGuard-managed ones. Shared by every router — was previously
    duplicated byte-for-byte in router_anthropic.py and router_openai.py,
    which risked one being updated (e.g. a new hop-by-hop header) without
    the other.

    For a repeated header name, the dict comprehension below keeps the
    *last* occurrence (later keys overwrite earlier ones) — this is the
    value that actually authenticates the upstream call, so
    _last_header_value() below must match it exactly. If they disagreed, a
    client sending two Authorization headers could get its session_id/
    initiating_principal derived from a throwaway first value while a real
    second value silently authenticates and executes the request upstream —
    letting it evade per-session rate limiting and lockouts at will while
    still successfully calling the real API.
    """
    strip = {"host", "content-length", "transfer-encoding", "connection"} | proxy_managed_headers(config)
    return {k: v for k, v in request.headers.items() if k.lower() not in strip}


def _last_header_value(request: Request, name: str, default: str = "") -> str:
    """Same "last occurrence wins" semantics as build_upstream_headers'
    dict comprehension — see its docstring for why this must match."""
    values = request.headers.getlist(name)
    return values[-1] if values else default


def extract_request_context(
    request: Request,
    config: ProxyConfig,
    body: dict[str, Any] | None = None,
    handler: Any | None = None,
) -> ProxyRequestContext:
    """
    Extract agent identity from the request.

    Priority:
    1. Custom X-AgentGuard-* headers, for goal/agent_id/framework only
       (explicit, self-asserted — see the agent_id note below for why these
       are never enforcement-authoritative either)
    2. Framework fingerprint from User-Agent / declared tool names
       (best-effort, auto-detected — see agentguard.proxy.fingerprint)
    3. Auth header hash — the ONLY source for session_id (see below)

    `body`/`handler` are optional so callers that only have headers (or
    existing tests) still work — framework then resolves to the "proxy"
    literal, identical to pre-fingerprinting behavior.
    """
    # Custom headers (highest priority for goal/agent_id/framework — NOT
    # session_id, see below)
    goal = request.headers.get(config.goal_header, "")[:_MAX_GOAL_LEN].strip()
    agent_id = request.headers.get(config.agent_id_header, "")[:_MAX_AGENT_ID_LEN].strip()
    explicit_framework = request.headers.get(config.framework_header, "")[:_MAX_FRAMEWORK_LEN].strip()

    # Auth header used for stable session derivation and initiating_principal
    # tracking. Must use _last_header_value (not request.headers.get, which
    # returns the *first* occurrence) so this matches the value
    # build_upstream_headers actually forwards and authenticates with — see
    # its docstring for the spoofing risk if these two ever disagreed.
    auth = _last_header_value(request, "Authorization") or _last_header_value(request, "x-api-key")
    auth_hash = hashlib.sha256(auth.encode()).hexdigest()[:16] if auth else ""

    # session_id is ALWAYS derived from the auth-hash (or a fresh anonymous
    # UUID when no auth info is present at all) — the client-supplied
    # X-AgentGuard-Session header is deliberately never consulted here. A
    # pentest found that header, when trusted, let a client trivially
    # defeat session_limits lockout/demotion and this proxy's rate limiter
    # (both keyed on session_id, agentguard/interceptor/interceptor.py and
    # router_anthropic.py/router_openai.py) simply by sending a fresh value
    # per request — no header trickery needed, just a normal single header
    # changed each time. Nothing in this repo's examples/tests relies on
    # that header being trusted for this, so dropping it is safe. Rotating
    # the *auth credential* itself still resets enforcement state, same as
    # before — an accepted, inherent limit of any credential-keyed
    # tracking, not something this fix can close — but doing so costs an
    # attacker a fresh, real, paid upstream API key per rotation rather
    # than a free client-chosen string.
    session_id = f"proxy-{auth_hash}" if auth_hash else str(uuid.uuid4())

    # Leave agent_id empty when not explicitly provided — a synthesized
    # placeholder here would make every proxy request look "provided" to
    # Interceptor.intercept()'s is_registered = bool(agent_id) check,
    # collapsing the registered/unregistered distinction entirely.
    if not goal:
        goal = "LLM API Proxy Agent"

    mismatch = None
    if explicit_framework:
        framework = explicit_framework  # explicit header short-circuits fingerprinting — nothing to cross-check
    else:
        from agentguard.proxy.fingerprint import detect_fingerprint_mismatch, fingerprint_framework
        tool_names = handler.extract_tool_names(body) if (handler is not None and body is not None) else []
        ua = request.headers.get("user-agent", "")
        framework = fingerprint_framework(tool_names, ua)
        mismatch = detect_fingerprint_mismatch(tool_names, ua)
        if mismatch is not None:
            logger.warning(
                "proxy_framework_signal_mismatch",
                claimed_framework=mismatch.claimed_framework,
                missing_markers=sorted(mismatch.missing_markers),
                session_id=session_id,
                detail=(
                    "User-Agent claims a known client but declared tool names "
                    "don't corroborate it. Descriptive only — does not affect "
                    "framework resolution or any enforcement decision."
                ),
            )

    # X-Request-ID set by RequestIDMiddleware before this runs
    correlation_id = (
        getattr(getattr(request, "state", None), "request_id", "")
        or str(uuid.uuid4())
    )[:_MAX_CORRELATION_ID_LEN]

    return ProxyRequestContext(
        agent_goal=goal,
        session_id=session_id,
        agent_id=agent_id,
        framework=framework,
        fingerprint_mismatch=mismatch,
        correlation_id=correlation_id,
        initiating_principal=f"proxy-key:{auth_hash}" if auth_hash else "proxy-anonymous",
    )
