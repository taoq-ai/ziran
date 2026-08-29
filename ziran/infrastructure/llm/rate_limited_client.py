"""Rate-limiting + retry decorator over any ``BaseLLMClient``.

Wraps an inner client so that all outbound provider calls are (1) paced by
client-side token buckets (rpm/tpm) and (2) retried with exponential backoff
on retryable provider errors (HTTP 429 and transient 5xx). Transparent: it
implements the same ``BaseLLMClient`` interface, so callers are unchanged.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from ziran.application.rate_limiting import (
    AsyncTokenBucket,
    RateLimitConfig,
    backoff_delay,
    is_retryable,
    retry_after,
    status_code,
)
from ziran.infrastructure.llm.base import BaseLLMClient, LLMConfig, LLMError, LLMResponse

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from ziran.domain.entities.streaming import LLMResponseChunk

logger = logging.getLogger(__name__)


class RateLimitedClient(BaseLLMClient):
    """Decorator adding token-bucket pacing and retry-with-backoff."""

    def __init__(
        self,
        inner: BaseLLMClient,
        config: LLMConfig,
        rate_config: RateLimitConfig,
    ) -> None:
        super().__init__(config)
        self._inner = inner
        self._rl = rate_config
        self._rpm_bucket = AsyncTokenBucket(rate_config.rpm)
        self._tpm_bucket = AsyncTokenBucket(rate_config.tpm)

    @staticmethod
    def _estimate_tokens(messages: list[dict[str, str]]) -> float:
        # ponytail: chars/4 heuristic (matches the many-shot estimator);
        # swap for tiktoken only if tpm pacing accuracy ever matters.
        chars = sum(len(m.get("content", "")) for m in messages)
        return max(1.0, chars / 4.0)

    async def _acquire(self, messages: list[dict[str, str]]) -> None:
        await self._rpm_bucket.acquire(1.0)
        if self._rl.tpm > 0:
            await self._tpm_bucket.acquire(self._estimate_tokens(messages))

    async def complete(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> LLMResponse:
        attempt = 0
        while True:
            await self._acquire(messages)
            try:
                return await self._inner.complete(
                    messages, temperature=temperature, max_tokens=max_tokens, **kwargs
                )
            except LLMError as exc:
                if not is_retryable(exc) or attempt >= self._rl.max_retries:
                    if is_retryable(exc) and attempt >= self._rl.max_retries:
                        msg = (
                            f"LLM call failed after {attempt} retries "
                            f"(provider throttled, status={status_code(exc)})"
                        )
                        raise LLMError(
                            msg, provider=exc.provider or self.config.provider, cause=exc
                        ) from exc
                    raise
                delay = max(retry_after(exc) or 0.0, backoff_delay(attempt, self._rl))
                logger.warning(
                    "provider throttled (provider=%s, status=%s), retrying %d/%d after %.2fs",
                    exc.provider or self.config.provider,
                    status_code(exc),
                    attempt + 1,
                    self._rl.max_retries,
                    delay,
                )
                await asyncio.sleep(delay)
                attempt += 1

    async def stream_complete(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[LLMResponseChunk]:
        # Rate-limit the slot acquisition; retry does not cover mid-stream
        # failures (see spec 029 Assumptions).
        await self._acquire(messages)
        async for chunk in self._inner.stream_complete(
            messages, temperature=temperature, max_tokens=max_tokens, **kwargs
        ):
            yield chunk

    async def health_check(self) -> bool:
        return await self._inner.health_check()
