"""Sliding-window rate limiter with Redis backend and in-memory fallback.

Primary: Redis-backed atomic sliding window using a Lua script.
Fallback: Process-local in-memory deque (original implementation).

Under multi-worker deployments (uvicorn --workers N) the in-memory fallback
gives per-process limits, so the effective limit is N × AGENTGUARD_RATE_LIMIT.
Configure REDIS_URL to enable accurate cross-process limiting.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections import defaultdict, deque

import structlog

logger = structlog.get_logger(__name__)

# Sentinel: means "read REDIS_URL from environment" (distinct from explicit None which disables Redis)
_UNSET = object()

# Lua script for atomic Redis sliding window.
# Returns 0 if allowed, 1 if rate limited.
_LUA_SLIDING_WINDOW = """
local key = KEYS[1]
local now_ms = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local cutoff = now_ms - window_ms
redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
local count = redis.call('ZCARD', key)
if count < limit then
  redis.call('ZADD', key, now_ms, tostring(now_ms) .. ':' .. tostring(math.random(1000000)))
  redis.call('PEXPIRE', key, window_ms + 1000)
  return 0
end
return 1
"""

# Warn about Redis fallback only once per process lifetime
_redis_fallback_warned = False


class RateLimiter:
    """
    Per-client sliding window rate limiter.

    Tries Redis first; falls back to process-local in-memory deque if Redis
    is unavailable or not configured. In-memory path is async-safe via asyncio.Lock.

    Empty buckets are evicted after pruning to prevent unbounded memory growth
    from many unique client IDs.

    Client key is typically the JWT subject (when auth is on) or IP address.

    Configured via env vars:
        AGENTGUARD_RATE_LIMIT        — requests per window (default: 120)
        AGENTGUARD_RATE_LIMIT_WINDOW — window in seconds (default: 60)
        REDIS_URL                    — Redis connection URL (optional)
    """

    def __init__(
        self,
        requests_per_window: int | None = None,
        window_seconds: float | None = None,
        redis_url: object = _UNSET,
    ) -> None:
        self._default_limit = requests_per_window or int(os.getenv("AGENTGUARD_RATE_LIMIT", "120"))
        self._default_window = window_seconds or float(os.getenv("AGENTGUARD_RATE_LIMIT_WINDOW", "60"))
        # In-memory fallback state
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()
        # Redis state: explicit None disables Redis (useful in tests); sentinel reads env
        if redis_url is _UNSET:
            self._redis_url = os.getenv("REDIS_URL", "")
        else:
            self._redis_url = redis_url or ""
        self._redis_client: object | None = None
        self._redis_script: object | None = None

    async def _get_redis_client(self):
        """Lazy-init the Redis client and register the Lua script."""
        if self._redis_client is None and self._redis_url:
            import redis.asyncio as aioredis
            self._redis_client = aioredis.from_url(self._redis_url, socket_connect_timeout=1)
            self._redis_script = self._redis_client.register_script(_LUA_SLIDING_WINDOW)
        return self._redis_client

    async def _check_redis(self, client_id: str, limit: int, window_ms: int) -> bool | None:
        """
        Attempt Redis check. Returns True if allowed, False if limited, None on error.
        """
        global _redis_fallback_warned
        if not self._redis_url:
            return None
        try:
            await self._get_redis_client()  # initialises self._redis_script as side-effect
            script = self._redis_script
            now_ms = int(time.time() * 1000)
            key = f"agentguard:rl:{client_id}"
            result = await script(keys=[key], args=[now_ms, window_ms, limit])
            return result == 0  # 0 = allowed, 1 = limited
        except Exception as exc:
            if not _redis_fallback_warned:
                logger.warning(
                    "rate_limiter_redis_unavailable_falling_back",
                    error=str(exc),
                )
                _redis_fallback_warned = True
            # Reset client so next call retries the connection
            self._redis_client = None
            self._redis_script = None
            return None

    async def is_allowed(
        self,
        client_id: str,
        limit: int | None = None,
        window: float | None = None,
    ) -> bool:
        """
        Return True if the request is within the rate limit.

        limit and window override the instance defaults — useful for applying
        stricter limits on sensitive endpoints (e.g. the /auth/token route).
        """
        effective_limit = limit if limit is not None else self._default_limit
        effective_window = window if window is not None else self._default_window
        window_ms = int(effective_window * 1000)

        # Attempt Redis check first
        redis_result = await self._check_redis(client_id, effective_limit, window_ms)
        if redis_result is not None:
            # Mirror the decision into the in-memory bucket so remaining() stays accurate
            if redis_result:
                now = time.monotonic()
                async with self._lock:
                    self._buckets[client_id].append(now)
            return redis_result

        # In-memory fallback
        now = time.monotonic()
        cutoff = now - effective_window

        async with self._lock:
            bucket = self._buckets[client_id]
            # Prune expired entries
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            # Evict the key entirely when the bucket is empty (prevents memory leak)
            if not bucket and client_id in self._buckets:
                del self._buckets[client_id]
                bucket = self._buckets[client_id]  # re-create via defaultdict
            if len(bucket) >= effective_limit:
                return False
            bucket.append(now)
            return True

    def remaining(self, client_id: str, limit: int | None = None, window: float | None = None) -> int:
        """Return how many requests remain in the current window (approximate, in-memory only)."""
        effective_limit = limit if limit is not None else self._default_limit
        effective_window = window if window is not None else self._default_window
        now = time.monotonic()
        cutoff = now - effective_window
        bucket = self._buckets.get(client_id)
        if not bucket:
            return effective_limit
        # Snapshot the deque to avoid RuntimeError from concurrent mutation
        # during iteration. list() on a deque is safe in an asyncio context
        # (single-threaded) — no await between .get() and list() means no
        # other coroutine can mutate the bucket.
        snapshot = list(bucket)
        active = sum(1 for t in snapshot if t >= cutoff)
        return max(0, effective_limit - active)


_limiter: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    global _limiter
    if _limiter is None:
        _limiter = RateLimiter()
    return _limiter


def reset_rate_limiter() -> None:
    """
    Reset the singleton — for use in tests only.

    Also flushes Redis rate limit keys so Redis state doesn't leak between tests.
    """
    global _limiter
    redis_url = os.getenv("REDIS_URL", "")
    if redis_url:
        try:
            import redis as _sync_redis
            client = _sync_redis.from_url(redis_url, socket_connect_timeout=1)
            keys = client.keys("agentguard:rl:*")
            if keys:
                client.delete(*keys)
            client.close()
        except Exception:
            pass  # Redis unavailable — nothing to flush
    _limiter = None
