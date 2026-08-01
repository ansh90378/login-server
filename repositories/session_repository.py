"""Refresh-token storage in Redis."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from core.config import settings
from core.redis import delete_key, exists_key, get_key, get_redis, set_key

_REFRESH_PREFIX = "refresh_token:"
_BLACKLIST_PREFIX = "blacklisted_token:"
_NOT_BEFORE_KEY = "global:not_before"


def _refresh_key(jti: str) -> str:
    return f"{_REFRESH_PREFIX}{jti}"


def _blacklist_key(jti: str) -> str:
    return f"{_BLACKLIST_PREFIX}{jti}"


class SessionRepository:
    """Manages refresh tokens and blacklists in Redis."""

    @staticmethod
    async def store_refresh_token(
        jti: str,
        user_id: str,
        family_id: str,
    ) -> None:
        data = json.dumps({
            "user_id": user_id,
            "family_id": family_id,
            "expires_at": datetime.now(timezone.utc).timestamp()
            + settings.REFRESH_TOKEN_TTL,
        })
        await set_key(_refresh_key(jti), data, ttl=settings.REFRESH_TOKEN_TTL)

    @staticmethod
    async def get_refresh_token(jti: str) -> dict | None:
        raw = await get_key(_refresh_key(jti))
        if raw is None:
            return None
        return json.loads(raw)

    @staticmethod
    async def delete_refresh_token(jti: str) -> None:
        await delete_key(_refresh_key(jti))

    @staticmethod
    async def blacklist_refresh_token(jti: str, original_ttl: int) -> None:
        """Blacklist a refresh token (e.g. on logout)."""
        await set_key(_blacklist_key(jti), "1", ttl=original_ttl)

    @staticmethod
    async def is_blacklisted(jti: str) -> bool:
        return await exists_key(_blacklist_key(jti))

    @staticmethod
    async def set_global_not_before(timestamp: int) -> None:
        """Set a global timestamp — tokens issued before this are invalid."""
        await set_key(_NOT_BEFORE_KEY, str(timestamp))

    @staticmethod
    async def get_global_not_before() -> int | None:
        raw = await get_key(_NOT_BEFORE_KEY)
        return int(raw) if raw else None