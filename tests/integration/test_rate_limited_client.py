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


@pytest.mark.integration
async def test_exhausted_retries_surface_as_failure() -> None:
    provider = _MockProvider(fail_first=100)  # never recovers
    cfg = RateLimitConfig(rpm=0, tpm=0, max_retries=2, base_delay=0.001, max_delay=0.01)
    client = RateLimitedClient(provider, provider.config, cfg)

    with pytest.raises(LLMError, match="after 2 retries"):
        await client.complete([{"role": "user", "content": "doomed"}])
