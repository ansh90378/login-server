"""Rate limiting middleware using Redis (falls back to no-op when unavailable)."""

from __future__ import annotations

import logging

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from core.config import settings
from core.exceptions import RateLimitExceededException
from core.redis import _dict_expire, _dict_incr, get_redis

logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP rate limiter backed by Redis.

    Gracefully degrades to no-op when Redis is unavailable (e.g. during tests).
    """

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        # Only rate-limit auth endpoints
        if not request.url.path.startswith("/api/v1/"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        key = f"ratelimit:{client_ip}:{request.url.path}"

        try:
            if settings.DISABLE_REDIS:
                current = await _dict_incr(key)
                if current == 1:
                    await _dict_expire(key, 60)
            else:
                redis_conn = get_redis()
                current = await redis_conn.incr(key)
                if current == 1:
                    await redis_conn.expire(key, 60)

            if current > 20:  # 20 requests per minute
                raise RateLimitExceededException()
        except Exception as exc:
            # If it's already our custom exception, re-raise it
            if isinstance(exc, RateLimitExceededException):
                raise
            # Otherwise Redis might be down — log and let the request through
            logger.warning("Rate limiter unavailable (Redis?), allowing request: %s", exc)

        return await call_next(request)