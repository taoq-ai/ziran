"""Configuration for client-side LLM rate-limiting and retry.

A single Pydantic model holds the requests-per-minute (``rpm``),
tokens-per-minute (``tpm``), and retry parameters. ``rpm``/``tpm`` of ``0``
disables the corresponding limiter. Per-provider defaults are exposed via
:meth:`RateLimitConfig.for_provider`.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

# Conservative per-provider defaults (requests per minute). Unknown providers
# fall back to a safe 60 rpm; operators raise it via CLI flags / env vars.
_PROVIDER_DEFAULT_RPM: dict[str, int] = {
    "openai": 10000,
    "anthropic": 4000,
    "bedrock": 4000,
    "azure": 10000,
}
_DEFAULT_RPM = 60


class RateLimitConfig(BaseModel):
    """Rate-limit and retry parameters for outbound LLM calls."""

    rpm: int = Field(default=_DEFAULT_RPM, ge=0, description="Requests per minute (0 disables)")
    tpm: int = Field(default=0, ge=0, description="Tokens per minute (0 disables)")
    max_retries: int = Field(default=3, ge=0, description="Retries for retryable provider errors")
    base_delay: float = Field(default=0.5, gt=0, description="Base backoff delay in seconds")
    max_delay: float = Field(default=30.0, gt=0, description="Maximum backoff delay in seconds")

    @classmethod
    def for_provider(
        cls,
        provider: str | None,
        *,
        rpm: int | None = None,
        tpm: int | None = None,
        max_retries: int | None = None,
    ) -> RateLimitConfig:
        """Build a config using per-provider default rpm, applying overrides.

        ``None`` overrides are ignored so callers can pass through optional
        CLI/env values without clobbering the provider default.
        """
        data: dict[str, int] = {
            "rpm": _PROVIDER_DEFAULT_RPM.get((provider or "").lower(), _DEFAULT_RPM)
        }
        if rpm is not None:
            data["rpm"] = rpm
        if tpm is not None:
            data["tpm"] = tpm
        if max_retries is not None:
            data["max_retries"] = max_retries
        return cls(**data)
