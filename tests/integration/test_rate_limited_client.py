"""Integration test: no attack lost under provider throttling at concurrency 20.

Spec 029 SC-001 / SC-003: a mock provider returns 429s at a known rate; every
call must still succeed through the rate-limited client, and 20 concurrent
calls must complete end to end.
"""

from __future__ import annotations

import asyncio

import pytest

from ziran.application.rate_limiting import RateLimitConfig
from ziran.infrastructure.llm.base import BaseLLMClient, LLMConfig, LLMError, LLMResponse
from ziran.infrastructure.llm.rate_limited_client import RateLimitedClient


class _Throttling429Error(Exception):
    """Stand-in for a provider rate-limit error."""

    def __init__(self) -> None:
        super().__init__("429 Too Many Requests")
        self.status_code = 429


class _MockProvider(BaseLLMClient):
    """Raises 429 for the first ``fail_first`` attempts of each distinct call.

    Also records the peak number of concurrently in-flight calls so the test
    can assert the 20 calls really ran in parallel.
    """

    def __init__(self, fail_first: int) -> None:
        super().__init__(LLMConfig(provider="litellm", model="gpt-4o"))
        self._fail_first = fail_first
        self._attempts: dict[str, int] = {}
        self.total_calls = 0
        self.in_flight = 0
        self.peak_in_flight = 0

    async def complete(self, messages, *, temperature=None, max_tokens=None, **kwargs):  # type: ignore[no-untyped-def]
        self.in_flight += 1
        self.peak_in_flight = max(self.peak_in_flight, self.in_flight)
        self.total_calls += 1
        try:
            await asyncio.sleep(0)  # yield so calls actually interleave
            key = messages[0]["content"]
            self._attempts[key] = self._attempts.get(key, 0) + 1
            if self._attempts[key] <= self._fail_first:
                raise LLMError("throttled", provider="litellm", cause=_Throttling429Error())
            return LLMResponse(content=f"done {key}", model="gpt-4o")
        finally:
            self.in_flight -= 1

    async def health_check(self) -> bool:
        return True


@pytest.mark.integration
async def test_no_attack_lost_at_concurrency_20() -> None:
    provider = _MockProvider(fail_first=2)  # each call is throttled twice, then succeeds
    cfg = RateLimitConfig(rpm=0, tpm=0, max_retries=3, base_delay=0.001, max_delay=0.01)
    client = RateLimitedClient(provider, provider.config, cfg)

    async def one(i: int) -> LLMResponse:
        return await client.complete([{"role": "user", "content": f"attack-{i}"}])

    results = await asyncio.gather(*(one(i) for i in range(20)))

    # No attack lost: every concurrent call produced a successful response.
    assert len(results) == 20
    assert all(r.content.startswith("done attack-") for r in results)
    # Each call retried twice then succeeded: 3 provider attempts each.
    assert provider.total_calls == 60
    # The 20 calls genuinely ran concurrently.
    assert provider.peak_in_flight > 1


class _StatusError(Exception):
    def __init__(self, status_code: int) -> None:
        super().__init__(f"status {status_code}")
        self.status_code = status_code


class _BucketAwareProvider(BaseLLMClient):
    """Provider that returns 429 whenever calls arrive faster than ``rpm``.

    It runs its own correct token bucket (same rate, capacity ``rpm``) on the
    shared virtual clock. If the client-side limiter ever admits a call the
    provider's bucket cannot afford, that is an over-limit arrival: the
    provider records a violation and raises 429. A correctly paced limiter
    stays in lock-step with this bucket and never trips it.
    """

    def __init__(self, clock: object, rpm: int) -> None:
        super().__init__(LLMConfig(provider="litellm", model="gpt-4o"))
        self._clock = clock  # callable returning virtual seconds
        self._rate = rpm
        self._capacity = float(rpm)
        self._tokens = float(rpm)
        self._updated = clock()  # type: ignore[operator]
        self.violations = 0
        self.total_calls = 0

    async def complete(self, messages, *, temperature=None, max_tokens=None, **kwargs):  # type: ignore[no-untyped-def]
        self.total_calls += 1
        now = self._clock()  # type: ignore[operator]
        self._tokens = min(self._capacity, self._tokens + (now - self._updated) * self._rate / 60.0)
        self._updated = now
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return LLMResponse(content="ok", model="gpt-4o")
        self.violations += 1
        raise LLMError("429 too many requests", provider="litellm", cause=_StatusError(429))

    async def health_check(self) -> bool:
        return True


@pytest.mark.integration
async def test_pacing_holds_under_concurrency_20() -> None:
    # Virtual clock shared by the limiter's bucket and the provider's bucket;
    # fake sleep advances it so pacing is deterministic and instant.
    now = [0.0]

    def clock() -> float:
        return now[0]

    async def fake_sleep(d: float) -> None:
        now[0] += d
        await asyncio.sleep(0)  # yield so other gathered tasks can run

    rpm = 6  # capacity 6 < 20 concurrent calls, so pacing MUST engage
    provider = _BucketAwareProvider(clock, rpm)
    cfg = RateLimitConfig(rpm=rpm, tpm=0, max_retries=5, base_delay=0.001, max_delay=0.001)
    client = RateLimitedClient(provider, provider.config, cfg, clock=clock, sleep=fake_sleep)

    async def one(i: int) -> LLMResponse:
        return await client.complete([{"role": "user", "content": f"attack-{i}"}])

    results = await asyncio.gather(*(one(i) for i in range(20)))

    # No attack lost.
    assert len(results) == 20
    assert all(r.content == "ok" for r in results)
    # The limiter never admitted faster than the provider's rate allowed.
    assert provider.violations == 0
    # Pacing actually engaged (14 post-burst calls each waited ~60/rpm=10s).
    assert now[0] == pytest.approx((20 - rpm) * 60 / rpm)


@pytest.mark.integration
async def test_exhausted_retries_surface_as_failure() -> None:
    provider = _MockProvider(fail_first=100)  # never recovers
    cfg = RateLimitConfig(rpm=0, tpm=0, max_retries=2, base_delay=0.001, max_delay=0.01)
    client = RateLimitedClient(provider, provider.config, cfg)

    with pytest.raises(LLMError, match="after 2 retries"):
        await client.complete([{"role": "user", "content": "doomed"}])
