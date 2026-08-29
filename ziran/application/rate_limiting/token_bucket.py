"""Async token-bucket limiter for pacing outbound calls.

Refills at ``rate`` units per minute up to a matching capacity. ``acquire``
waits (via injected ``sleep``) until enough tokens are available. A ``rate``
of ``0`` disables the bucket (``acquire`` returns immediately).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable


class AsyncTokenBucket:
    """A simple async token bucket. Not safe across event loops.

    ponytail: single asyncio.Lock, correct for one campaign's event loop at
    concurrency ~20; shard per-key only if a multi-loop use appears.
    """

    def __init__(
        self,
        rate: int,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._rate = rate  # units per minute; 0 disables
        self._capacity = float(rate)
        self._tokens = float(rate)
        self._clock = clock
        self._sleep = sleep
        self._updated = clock()
        self._lock = asyncio.Lock()

    async def acquire(self, amount: float = 1.0) -> None:
        """Wait until ``amount`` tokens are available, then consume them."""
        if self._rate <= 0:
            return
        # Never wait forever for a request larger than the whole bucket.
        amount = min(amount, self._capacity)
        async with self._lock:
            while True:
                now = self._clock()
                self._tokens = min(
                    self._capacity,
                    self._tokens + (now - self._updated) * self._rate / 60.0,
                )
                self._updated = now
                if self._tokens >= amount:
                    self._tokens -= amount
                    return
                wait = (amount - self._tokens) * 60.0 / self._rate
                await self._sleep(wait)
