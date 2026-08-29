"""Retry classification and exponential backoff for LLM provider errors.

The provider exception is inspected without importing any provider SDK
(litellm is optional). An error is retryable when it (or its ``__cause__``)
carries a retryable HTTP status code, or its type name matches a known
transient-error pattern.
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ziran.application.rate_limiting.config import RateLimitConfig

# HTTP 429 (rate limited) plus transient 5xx.
_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
_RETRYABLE_NAME_HINTS = (
    "ratelimit",
    "timeout",
    "apiconnection",
    "serviceunavailable",
    "internalserver",
)


def _chain(exc: BaseException) -> list[BaseException]:
    cause = getattr(exc, "__cause__", None)
    return [exc, cause] if cause is not None else [exc]


def status_code(exc: BaseException) -> int | None:
    """Return the HTTP status code carried by the exception or its cause."""
    for e in _chain(exc):
        code = getattr(e, "status_code", None)
        if isinstance(code, int):
            return code
    return None


def is_retryable(exc: BaseException) -> bool:
    """Whether a provider error should be retried (429 / transient 5xx)."""
    for e in _chain(exc):
        code = getattr(e, "status_code", None)
        if isinstance(code, int) and code in _RETRYABLE_STATUS:
            return True
        name = type(e).__name__.lower()
        if any(hint in name for hint in _RETRYABLE_NAME_HINTS):
            return True
    return False


def retry_after(exc: BaseException) -> float | None:
    """Extract a provider-supplied ``Retry-After`` value (seconds), if any."""
    for e in _chain(exc):
        val = getattr(e, "retry_after", None)
        if val is not None:
            try:
                return float(val)
            except (TypeError, ValueError):
                pass
        headers = getattr(getattr(e, "response", None), "headers", None)
        if headers:
            raw = headers.get("retry-after") or headers.get("Retry-After")
            if raw:
                try:
                    return float(raw)
                except (TypeError, ValueError):
                    pass
    return None


def backoff_delay(attempt: int, config: RateLimitConfig) -> float:
    """Full-jitter exponential backoff: uniform(0, min(cap, base * 2**attempt)).

    Full jitter avoids a thundering herd when many concurrent calls back off
    together.
    """
    ceiling = min(config.max_delay, config.base_delay * (2**attempt))
    return random.uniform(0.0, ceiling)
