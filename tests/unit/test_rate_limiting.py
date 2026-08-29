"""Unit tests for the LLM rate-limiting + retry core (spec 029)."""

from __future__ import annotations

import logging
from typing import ClassVar

import pytest
from pydantic import ValidationError

from ziran.application.rate_limiting import (
    AsyncTokenBucket,
    RateLimitConfig,
    backoff_delay,
    is_retryable,
    retry_after,
    status_code,
)
from ziran.infrastructure.llm.base import BaseLLMClient, LLMConfig, LLMError, LLMResponse
from ziran.infrastructure.llm.rate_limited_client import RateLimitedClient

# ══════════════════════════════════════════════════════════════════════
# RateLimitConfig
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.unit
class TestRateLimitConfig:
    def test_defaults(self) -> None:
        cfg = RateLimitConfig()
        assert cfg.rpm == 60
        assert cfg.tpm == 0
        assert cfg.max_retries == 3
        assert cfg.base_delay > 0
        assert cfg.max_delay > 0

    def test_for_provider_defaults(self) -> None:
        assert RateLimitConfig.for_provider("openai").rpm == 10000
        assert RateLimitConfig.for_provider("anthropic").rpm == 4000
        assert RateLimitConfig.for_provider("litellm").rpm == 60
        assert RateLimitConfig.for_provider(None).rpm == 60

    def test_for_provider_overrides(self) -> None:
        cfg = RateLimitConfig.for_provider("openai", rpm=120, tpm=9000, max_retries=5)
        assert cfg.rpm == 120
        assert cfg.tpm == 9000
        assert cfg.max_retries == 5
        # None overrides are ignored (fall back to provider default)
        assert RateLimitConfig.for_provider("openai", rpm=None).rpm == 10000

    def test_non_negative(self) -> None:
        with pytest.raises(ValidationError):
            RateLimitConfig(rpm=-1)
        with pytest.raises(ValidationError):
            RateLimitConfig(max_retries=-1)


# ══════════════════════════════════════════════════════════════════════
# retry classification + backoff
# ══════════════════════════════════════════════════════════════════════


class _StatusError(Exception):
    def __init__(self, status_code: int) -> None:
        super().__init__(f"status {status_code}")
        self.status_code = status_code


@pytest.mark.unit
class TestRetryClassification:
    @pytest.mark.parametrize("code", [429, 500, 502, 503, 504])
    def test_retryable_status_codes(self, code: int) -> None:
        assert is_retryable(_StatusError(code)) is True

    @pytest.mark.parametrize("code", [400, 401, 403, 404, 422])
    def test_non_retryable_status_codes(self, code: int) -> None:
        assert is_retryable(_StatusError(code)) is False

    def test_status_on_cause(self) -> None:
        exc = LLMError("wrapped", provider="litellm", cause=_StatusError(429))
        assert is_retryable(exc) is True
        assert status_code(exc) == 429

    def test_type_name_fallback(self) -> None:
        class RateLimitError(Exception):
            pass

        assert is_retryable(RateLimitError()) is True

        class BadInputError(Exception):
            pass

        assert is_retryable(BadInputError()) is False

    def test_retry_after_from_attr(self) -> None:
        exc = _StatusError(429)
        exc.retry_after = 7  # type: ignore[attr-defined]
        assert retry_after(exc) == 7.0

    def test_retry_after_from_headers(self) -> None:
        class _Resp:
            headers: ClassVar[dict[str, str]] = {"retry-after": "3"}

        exc = _StatusError(429)
        exc.response = _Resp()  # type: ignore[attr-defined]
        assert retry_after(exc) == 3.0

    def test_retry_after_absent(self) -> None:
        assert retry_after(_StatusError(429)) is None


@pytest.mark.unit
class TestBackoffDelay:
    def test_within_jitter_cap(self) -> None:
        cfg = RateLimitConfig(base_delay=0.5, max_delay=30.0)
        for attempt in range(6):
            delay = backoff_delay(attempt, cfg)
            cap = min(cfg.max_delay, cfg.base_delay * (2**attempt))
            assert 0.0 <= delay <= cap

    def test_capped(self) -> None:
        cfg = RateLimitConfig(base_delay=1.0, max_delay=4.0)
        # 2**10 * 1.0 is far above the cap; jittered result must stay <= cap
        assert backoff_delay(10, cfg) <= 4.0


# ══════════════════════════════════════════════════════════════════════
# AsyncTokenBucket
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.unit
class TestAsyncTokenBucket:
    async def test_disabled_never_waits(self) -> None:
        elapsed: list[float] = []

        async def fake_sleep(d: float) -> None:
            elapsed.append(d)

        bucket = AsyncTokenBucket(0, clock=lambda: 0.0, sleep=fake_sleep)
        for _ in range(100):
            await bucket.acquire()
        assert elapsed == []

    async def test_paces_when_over_rate(self) -> None:
        clock = [0.0]

        async def fake_sleep(d: float) -> None:
            clock[0] += d

        bucket = AsyncTokenBucket(60, clock=lambda: clock[0], sleep=fake_sleep)
        # Drain the full capacity at t=0 (no wait needed).
        for _ in range(60):
            await bucket.acquire()
        assert clock[0] == 0.0
        # The next token must wait ~1s (refill is 1 token/sec at 60 rpm).
        await bucket.acquire()
        assert clock[0] == pytest.approx(1.0)

    async def test_amount_capped_to_capacity(self) -> None:
        clock = [0.0]

        async def fake_sleep(d: float) -> None:
            clock[0] += d

        bucket = AsyncTokenBucket(60, clock=lambda: clock[0], sleep=fake_sleep)
        # Requesting more than capacity must not loop forever.
        await bucket.acquire(1000)
        assert clock[0] >= 0.0


# ══════════════════════════════════════════════════════════════════════
# RateLimitedClient
# ══════════════════════════════════════════════════════════════════════


class _ScriptedClient(BaseLLMClient):
    """Inner client that raises a scripted sequence of errors, then succeeds."""

    def __init__(self, errors: list[Exception | None]) -> None:
        super().__init__(LLMConfig(provider="litellm", model="gpt-4o"))
        self._errors = errors
        self.calls = 0

    async def complete(self, messages, *, temperature=None, max_tokens=None, **kwargs):  # type: ignore[no-untyped-def]
        idx = self.calls
        self.calls += 1
        err = self._errors[idx] if idx < len(self._errors) else None
        if err is not None:
            raise err
        return LLMResponse(content="ok", model="gpt-4o")

    async def health_check(self) -> bool:
        return True


def _rl(inner: BaseLLMClient, **rl: object) -> RateLimitedClient:
    params: dict[str, object] = {
        "rpm": 0,
        "tpm": 0,
        "max_retries": 2,
        "base_delay": 0.001,
        "max_delay": 0.001,
    }
    params.update(rl)
    cfg = RateLimitConfig(**params)  # type: ignore[arg-type]
    return RateLimitedClient(inner, inner.config, cfg)


@pytest.mark.unit
class TestRateLimitedClient:
    async def test_retries_then_succeeds(self) -> None:
        err = LLMError("throttled", provider="litellm", cause=_StatusError(429))
        inner = _ScriptedClient([err, err, None])
        client = _rl(inner)
        resp = await client.complete([{"role": "user", "content": "hi"}])
        assert resp.content == "ok"
        assert inner.calls == 3  # 2 retries + success

    async def test_non_retryable_raises_immediately(self) -> None:
        err = LLMError("bad request", provider="litellm", cause=_StatusError(400))
        inner = _ScriptedClient([err, None])
        client = _rl(inner)
        with pytest.raises(LLMError):
            await client.complete([{"role": "user", "content": "hi"}])
        assert inner.calls == 1  # no retry

    async def test_exhausted_retries_raises_with_count(self) -> None:
        err = LLMError("throttled", provider="litellm", cause=_StatusError(429))
        inner = _ScriptedClient([err, err, err, err])
        client = _rl(inner)
        with pytest.raises(LLMError, match="2 retries"):
            await client.complete([{"role": "user", "content": "hi"}])
        assert inner.calls == 3  # max_retries=2 → 3 total attempts

    async def test_happy_path_no_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        inner = _ScriptedClient([None])
        client = _rl(inner)
        with caplog.at_level(logging.WARNING):
            await client.complete([{"role": "user", "content": "hi"}])
        assert "throttled" not in caplog.text

    async def test_retry_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        err = LLMError("throttled", provider="litellm", cause=_StatusError(429))
        inner = _ScriptedClient([err, None])
        client = _rl(inner)
        with caplog.at_level(logging.WARNING):
            await client.complete([{"role": "user", "content": "hi"}])
        assert "throttled" in caplog.text.lower()
        assert "429" in caplog.text

    async def test_health_check_delegates(self) -> None:
        inner = _ScriptedClient([None])
        client = _rl(inner)
        assert await client.health_check() is True

    async def test_honors_retry_after_over_backoff(self) -> None:
        # Retry-After (5s) must win over the tiny computed backoff. Inject a
        # sleep that records the delay so we can assert which value was used.
        slept: list[float] = []

        async def rec_sleep(d: float) -> None:
            slept.append(d)

        cause = _StatusError(429)
        cause.retry_after = 5  # type: ignore[attr-defined]
        err = LLMError("throttled", provider="litellm", cause=cause)
        inner = _ScriptedClient([err, None])
        cfg = RateLimitConfig(rpm=0, tpm=0, max_retries=2, base_delay=0.001, max_delay=0.001)
        client = RateLimitedClient(inner, inner.config, cfg, sleep=rec_sleep)

        resp = await client.complete([{"role": "user", "content": "hi"}])
        assert resp.content == "ok"
        assert slept  # a backoff sleep happened
        # The slept delay is the Retry-After value, not the ~0.001s backoff.
        assert slept[0] == pytest.approx(5.0)

    async def test_tpm_bucket_paced(self) -> None:
        # tpm > 0 exercises the token-estimate + tpm acquire path.
        inner = _ScriptedClient([None])
        client = _rl(inner, tpm=100000)
        resp = await client.complete([{"role": "user", "content": "hello world"}])
        assert resp.content == "ok"

    async def test_stream_complete_delegates(self) -> None:
        inner = _ScriptedClient([None])
        client = _rl(inner)
        chunks = [c async for c in client.stream_complete([{"role": "user", "content": "hi"}])]
        assert chunks  # inner's default streaming yields a final chunk
        assert chunks[-1].is_final is True
