"""Redis client wrapper.

When ``settings.DISABLE_REDIS`` is true, falls back to an in-process
dict-backed store so the server can run with no Redis server. The
dict store is process-local and does not persist across restarts, but
supports the same async key/value API used by the session repository.
"""

from __future__ import annotations

import time
from typing import Any

import redis.asyncio as aioredis

from core.config import settings

_redis: aioredis.Redis | None = None
_store: dict[str, tuple[str, float | None]] = {}


def get_redis() -> aioredis.Redis:
    """Return the global Redis client, creating it if necessary."""
    global _redis  # noqa: PLW0603
    if _redis is None:
        _redis = aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
    return _redis


async def close_redis() -> None:
    """Close the Redis connection pool."""
    global _redis  # noqa: PLW0603
    if _redis is not None:
        await _redis.aclose()
        _redis = None


# ── In-process dict store (used when DISABLE_REDIS=true) ────────────────


def _expired(key: str) -> bool:
    entry = _store.get(key)
    if entry is None:
        return True
    _, expires_at = entry
    if expires_at is None:
        return False
    if time.monotonic() >= expires_at:
        _store.pop(key, None)
        return True
    return False


async def _dict_set(key: str, value: Any, ttl: int | None = None) -> None:
    expires_at = (time.monotonic() + ttl) if ttl else None
    _store[key] = (str(value), expires_at)


async def _dict_get(key: str) -> str | None:
    if _expired(key):
        return None
    return _store[key][0]


async def _dict_delete(key: str) -> None:
    _store.pop(key, None)


async def _dict_exists(key: str) -> bool:
    return not _expired(key)


async def _dict_incr(key: str) -> int:
    entry = _store.get(key)
    if entry is None or _expired(key):
        _store[key] = ("1", None)
        return 1
    n = int(entry[0]) + 1
    _store[key] = (str(n), entry[1])
    return n


async def _dict_expire(key: str, ttl: int) -> bool:
    entry = _store.get(key)
    if entry is None or _expired(key):
        return False
    _store[key] = (entry[0], time.monotonic() + ttl)
    return True


# ── Convenience helpers ──────────────────────────────────────────────────


async def set_key(key: str, value: Any, ttl: int | None = None) -> None:
    if settings.DISABLE_REDIS:
        await _dict_set(key, value, ttl)
        return
    r = get_redis()
    await r.set(key, value, ex=ttl)


async def get_key(key: str) -> str | None:
    if settings.DISABLE_REDIS:
        return await _dict_get(key)
    r = get_redis()
    return await r.get(key)


async def delete_key(key: str) -> None:
    if settings.DISABLE_REDIS:
        await _dict_delete(key)
        return
    r = get_redis()
    await r.delete(key)


async def exists_key(key: str) -> bool:
    if settings.DISABLE_REDIS:
        return await _dict_exists(key)
    r = get_redis()
    return await r.exists(key) > 0
