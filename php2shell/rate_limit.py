from __future__ import annotations

import asyncio


class RateLimiter:
    """Global monotonic start-rate limiter for network operations."""

    def __init__(self, rate: float) -> None:
        if rate <= 0:
            raise ValueError("Scan rate must be greater than zero")
        self._interval = 1.0 / rate
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            if self._next > now:
                await asyncio.sleep(self._next - now)
                now = loop.time()
            self._next = max(now, self._next) + self._interval
