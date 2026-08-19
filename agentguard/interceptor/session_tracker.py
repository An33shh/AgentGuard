"""Per-session action/blocked counters and recent-action history, with a
Redis backend and in-memory fallback -- same two-tier design as
agentguard.auth.rate_limiter.RateLimiter, for the same reason.

Interceptor used to keep this state in a plain in-memory dict
(_session_stats/_session_history), which is only correct for a single
process. Every session_limits enforcement decision (max_actions,
max_blocked) and every session's action history for multi-step attack
detection were invisible across replicas: run more than one proxy/API
process and each one enforced its own independent counters, so an agent
could round-robin across replicas and get N times the configured limit
before any single replica's counter tripped. router_admin.py's endpoints
(GET/POST /admin/sessions/{id}) had this exact gap documented in their own
module docstring already -- this closes it.

session_limits state has no time window or decay by design (see
Interceptor.get_session_stats's docstring) -- once a limit is reached it
stays reached until an explicit reset_session call, so unlike the rate
limiter's sliding-window keys, these Redis keys carry no TTL.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections import defaultdict
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# Sentinel: means "read REDIS_URL from environment" (distinct from explicit None which disables Redis)
_UNSET = object()

# Atomically check session_limits and, if not already exceeded, reserve one
# action slot -- mirrors evaluate_session_limits' "either limit blocks"
# semantics (agentguard/policy/engine.py) inside a single Redis round-trip
# so concurrent requests across replicas can't all read a stale count and
# all pass the check before any of them increments (the same TOCTOU class
# rate_limiter.py's Lua script exists to close, just for a different
# counter shape). max_actions/max_blocked of 0 means "no limit" (matches
# SessionLimits' own "0/None disables" convention).
_LUA_RESERVE_ACTION_SLOT = """
local actions = tonumber(redis.call('GET', KEYS[1]) or '0')
local blocked = tonumber(redis.call('GET', KEYS[2]) or '0')
local max_actions = tonumber(ARGV[1])
local max_blocked = tonumber(ARGV[2])
local limited = 0
if (max_actions > 0 and actions >= max_actions) or (max_blocked > 0 and blocked >= max_blocked) then
  limited = 1
else
  actions = redis.call('INCR', KEYS[1])
end
return {limited, actions, blocked}
"""

_redis_fallback_warned = False


class SessionTracker:
    """
    Tracks, per session_id: an actions counter, a blocked counter, and a
    bounded recent-action history (for multi-step attack detection context).

    Tries Redis first; falls back to a process-local in-memory dict guarded
    by an asyncio.Lock if Redis is unavailable or not configured -- correct
    for a single process, same as before this class existed.

    Configured via:
        REDIS_URL — Redis connection URL (optional; same env var the rate
                     limiter and Redis Streams enrichment already use)
    """

    def __init__(self, redis_url: object = _UNSET, history_max: int = 5) -> None:
        self._history_max = history_max
        # In-memory fallback state
        self._buckets: dict[str, dict[str, int]] = defaultdict(lambda: {"actions": 0, "blocked": 0})
        self._history: dict[str, list[dict[str, str]]] = defaultdict(list)
        self._lock = asyncio.Lock()
        # Redis state: explicit None disables Redis (useful in tests); sentinel reads env
        self._redis_url: str
        if redis_url is _UNSET:
            self._redis_url = os.getenv("REDIS_URL", "")
        else:
            self._redis_url = str(redis_url) if redis_url else ""
        self._redis_client: Any | None = None
        self._redis_reserve_script: Any | None = None

    async def _get_redis_client(self):
        """Lazy-init the Redis client and register the Lua script."""
        if self._redis_client is None and self._redis_url:
            import redis.asyncio as aioredis
            self._redis_client = aioredis.from_url(self._redis_url, socket_connect_timeout=1)
            self._redis_reserve_script = self._redis_client.register_script(_LUA_RESERVE_ACTION_SLOT)
        return self._redis_client

    def _keys(self, session_id: str) -> tuple[str, str, str]:
        return (
            f"agentguard:session:{session_id}:actions",
            f"agentguard:session:{session_id}:blocked",
            f"agentguard:session:{session_id}:history",
        )

    async def _redis_call(self, fn):
        """Run a Redis operation, falling back to None (signaling "use the
        in-memory path") on any connection error -- same fail-soft posture
        as rate_limiter.py's _check_redis, so a Redis outage degrades
        session enforcement to per-process (still correct, just not
        cross-replica) instead of taking the whole proxy down. Fail-closed
        for the *security decision itself* is handled elsewhere (analyzer/
        guardrail); a tracking-state outage failing open to per-process
        counting is the same tradeoff the rate limiter already makes."""
        global _redis_fallback_warned
        if not self._redis_url:
            return None
        try:
            await self._get_redis_client()
            return await fn()
        except Exception as exc:
            if not _redis_fallback_warned:
                logger.warning("session_tracker_redis_unavailable_falling_back", error=str(exc))
                _redis_fallback_warned = True
            self._redis_client = None
            self._redis_reserve_script = None
            return None

    async def reserve_action_slot(
        self, session_id: str, max_actions: int, max_blocked: int,
    ) -> tuple[bool, int, int]:
        """
        Atomically check session_limits and, if neither limit is already
        exceeded, increment the actions counter.

        Returns (limited, actions, blocked) -- both counts are read at the
        same instant as the limit check (the pre-increment actions value
        when limited, since nothing was reserved in that case): callers use
        them for two purposes that both need this exact consistent
        snapshot, not a value some other concurrent request has since
        changed -- (1) the demotion/effective-thresholds calculation
        (agentguard/policy/engine.py's effective_thresholds) and (2)
        reconstructing the same PolicyViolation
        (policy.evaluate_session_limits(actions, blocked)) the tracker's
        own decision was based on, for the blocked-response's event detail.
        """
        actions_key, blocked_key, _ = self._keys(session_id)

        async def _call():
            script = self._redis_reserve_script
            if script is None:
                return None
            result = await script(keys=[actions_key, blocked_key], args=[max_actions or 0, max_blocked or 0])
            limited, actions, blocked = result
            return bool(limited), int(actions), int(blocked)

        redis_result = await self._redis_call(_call)
        if redis_result is not None:
            return redis_result

        async with self._lock:
            stats = self._buckets[session_id]
            current_actions = stats["actions"]
            current_blocked = stats["blocked"]
            limited = bool(
                (max_actions and current_actions >= max_actions)
                or (max_blocked and current_blocked >= max_blocked)
            )
            if not limited:
                stats["actions"] += 1
            return limited, current_actions, current_blocked

    async def increment_actions(self, session_id: str) -> None:
        """Unconditional +1 to the actions counter -- used only on the
        session-limit-block path, where the atomic reserve above
        deliberately did NOT increment (matches evaluate_session_limits'
        pre-fix behavior: a request that hits the limit still counts as an
        attempted action, recorded after the fact rather than reserved
        ahead of time, since there was nothing to reserve for a blocked
        request)."""
        actions_key, _, _ = self._keys(session_id)

        async def _call():
            await self._redis_client.incr(actions_key)
            return True

        if await self._redis_call(_call) is not None:
            return
        async with self._lock:
            self._buckets[session_id]["actions"] += 1

    async def increment_blocked(self, session_id: str) -> None:
        """Unconditional +1 to the blocked counter."""
        _, blocked_key, _ = self._keys(session_id)

        async def _call():
            await self._redis_client.incr(blocked_key)
            return True

        if await self._redis_call(_call) is not None:
            return
        async with self._lock:
            self._buckets[session_id]["blocked"] += 1

    async def append_history(self, session_id: str, entry: dict[str, str]) -> None:
        """Append one action-history entry, keeping only the most recent
        history_max entries -- used as recent-session context for
        multi-step attack detection (Interceptor._intercept_inner passes
        this to the analyzer)."""
        _, _, history_key = self._keys(session_id)
        payload = json.dumps(entry)

        async def _call():
            await self._redis_client.rpush(history_key, payload)
            await self._redis_client.ltrim(history_key, -self._history_max, -1)
            return True

        if await self._redis_call(_call) is not None:
            return
        async with self._lock:
            history = self._history[session_id]
            history.append(entry)
            if len(history) > self._history_max:
                self._history[session_id] = history[-self._history_max:]

    async def get_history(self, session_id: str) -> list[dict[str, str]]:
        _, _, history_key = self._keys(session_id)

        async def _call():
            raw = await self._redis_client.lrange(history_key, 0, -1)
            return [json.loads(item) for item in raw]

        redis_result = await self._redis_call(_call)
        if redis_result is not None:
            return redis_result
        async with self._lock:
            return list(self._history[session_id])

    async def get_stats(self, session_id: str) -> dict[str, int]:
        actions_key, blocked_key, _ = self._keys(session_id)

        async def _call():
            actions, blocked = await self._redis_client.mget(actions_key, blocked_key)
            return {"actions": int(actions or 0), "blocked": int(blocked or 0)}

        redis_result = await self._redis_call(_call)
        if redis_result is not None:
            return redis_result
        async with self._lock:
            stats = self._buckets.get(session_id, {"actions": 0, "blocked": 0})
            return dict(stats)

    async def reset(self, session_id: str) -> bool:
        """Clear a session's counters and history. Returns False if the
        session had no recorded state to reset."""
        actions_key, blocked_key, history_key = self._keys(session_id)

        async def _call():
            existed = await self._redis_client.exists(actions_key, blocked_key, history_key)
            await self._redis_client.delete(actions_key, blocked_key, history_key)
            return bool(existed)

        redis_result = await self._redis_call(_call)
        if redis_result is not None:
            return redis_result
        async with self._lock:
            existed = session_id in self._buckets
            self._buckets.pop(session_id, None)
            self._history.pop(session_id, None)
            return existed


_tracker: SessionTracker | None = None


def get_session_tracker() -> SessionTracker:
    global _tracker
    if _tracker is None:
        _tracker = SessionTracker()
    return _tracker


def reset_session_tracker() -> None:
    """Reset the singleton -- for use in tests only. Also flushes Redis
    session-tracker keys so Redis state doesn't leak between tests."""
    global _tracker
    redis_url = os.getenv("REDIS_URL", "")
    if redis_url:
        try:
            import redis as _sync_redis
            client = _sync_redis.from_url(redis_url, socket_connect_timeout=1)
            keys = client.keys("agentguard:session:*")
            if keys:
                client.delete(*keys)  # type: ignore[misc]
            client.close()
        except Exception:  # noqa: S110 — Redis unavailable, nothing to flush
            pass
    _tracker = None
