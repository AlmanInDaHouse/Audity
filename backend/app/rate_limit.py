from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Awaitable, Callable

from fastapi import HTTPException, Request, status
from redis.asyncio import Redis

from app.config import get_settings


class RateLimiter:
    def __init__(self) -> None:
        self.settings = get_settings()
        self._memory = defaultdict(int)
        self._memory_expiry: dict[str, int] = {}
        self._redis: Redis | None = None

    async def startup(self) -> None:
        try:
            self._redis = Redis.from_url(self.settings.redis_url, decode_responses=True)
            await self._redis.ping()
        except Exception:
            # why this: avoid hard-failing local dev/tests when Redis is unavailable.
            self._redis = None

    async def shutdown(self) -> None:
        if self._redis is not None:
            await self._redis.close()

    async def check(self, key: str, limit: int) -> None:
        window = int(time.time() // 60)
        composed = f'rl:{key}:{window}'
        if self._redis is not None:
            hits = await self._redis.incr(composed)
            if hits == 1:
                await self._redis.expire(composed, 61)
            if hits > limit:
                raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail='Rate limit exceeded')
            return

        if self._memory_expiry.get(composed, 0) < int(time.time()):
            self._memory[composed] = 0
            self._memory_expiry[composed] = int(time.time()) + 61
        self._memory[composed] += 1
        if self._memory[composed] > limit:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail='Rate limit exceeded')


rate_limiter = RateLimiter()


async def rate_limit_middleware(request: Request, call_next: Callable[[Request], Awaitable]):
    if request.url.path not in {'/health', '/docs', '/openapi.json'}:
        client_ip = request.client.host if request.client else 'unknown'
        await rate_limiter.check(f'{client_ip}:global', rate_limiter.settings.rate_limit_per_minute)
    return await call_next(request)


async def enforce_sensitive_limit(request: Request) -> None:
    client_ip = request.client.host if request.client else 'unknown'
    await rate_limiter.check(f'{client_ip}:sensitive:{request.url.path}', rate_limiter.settings.sensitive_rate_limit_per_minute)
