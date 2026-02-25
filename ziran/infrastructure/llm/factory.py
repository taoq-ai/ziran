"""LLM client factory.

Creates the appropriate LLM client based on configuration.
Currently supports LiteLLM as the primary backend (which itself
supports 100+ providers).
"""

from __future__ import annotations

import os

from ziran.infrastructure.llm.base import BaseLLMClient, LLMConfig


def create_llm_client(
    provider: str = "litellm",
    model: str = "gpt-4o",
    *,
    api_key_env: str | None = None,
    base_url: str | None = None,
    temperature: float = 0.0,
    max_tokens: int = 4096,
    config: LLMConfig | None = None,
) -> BaseLLMClient:
    """Create an LLM client for the given provider.

    Either pass a pre-built ``LLMConfig`` or individual parameters.
    Individual parameters are ignored if ``config`` is provided.

    Args:
        provider: LLM provider name.
        model: Model identifier.
        api_key_env: Env var name for the API key.
        base_url: Override base URL.
        temperature: Default sampling temperature.
        max_tokens: Default max response tokens.
        config: Pre-built configuration (overrides all other params).

    Returns:
        Configured LLM client instance.

    Raises:
        ValueError: If the provider is not supported.

    Example:
        ```python
        client = create_llm_client(
            provider="litellm",
            model="claude-sonnet-4-20250514",
            api_key_env="ANTHROPIC_API_KEY",
        )
        ```
    """
    if config is None:
        config = LLMConfig(
            provider=provider,
            model=model,
            api_key_env=api_key_env,
            base_url=base_url,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    if config.provider == "litellm":
        from ziran.infrastructure.llm.litellm_client import LiteLLMClient

        return LiteLLMClient(config)

    # For convenience, route common provider names through LiteLLM
    # since it already handles them via model-name prefixes.
    if config.provider in ("openai", "anthropic", "bedrock", "azure", "ollama", "groq"):
        from ziran.infrastructure.llm.litellm_client import LiteLLMClient

        return LiteLLMClient(config)

    msg = (
        f"Unsupported LLM provider: '{config.provider}'. "
        "Supported: 'litellm' (recommended), 'openai', 'anthropic', "
        "'bedrock', 'azure', 'ollama', 'groq'."
    )
    raise ValueError(msg)


def create_llm_client_from_env() -> BaseLLMClient | None:
    """Create an LLM client from environment variables.

    Reads ``ZIRAN_LLM_PROVIDER`` and ``ZIRAN_LLM_MODEL`` from the
    environment. Returns ``None`` if neither is set.

    Environment variables:
        ZIRAN_LLM_PROVIDER: Provider name (default: 'litellm').
        ZIRAN_LLM_MODEL: Model name (default: 'gpt-4o').
        ZIRAN_LLM_API_KEY_ENV: Env var name for the API key.
        ZIRAN_LLM_BASE_URL: Override base URL.
        ZIRAN_LLM_TEMPERATURE: Sampling temperature.
        ZIRAN_LLM_MAX_TOKENS: Max response tokens.

    Returns:
        Configured LLM client, or None if LLM is not configured.
    """
    provider = os.environ.get("ZIRAN_LLM_PROVIDER")
    model = os.environ.get("ZIRAN_LLM_MODEL")

    if not provider and not model:
        return None

    config = LLMConfig(
        provider=provider or "litellm",
        model=model or "gpt-4o",
        api_key_env=os.environ.get("ZIRAN_LLM_API_KEY_ENV"),
        base_url=os.environ.get("ZIRAN_LLM_BASE_URL"),
        temperature=float(os.environ.get("ZIRAN_LLM_TEMPERATURE", "0.0")),
        max_tokens=int(os.environ.get("ZIRAN_LLM_MAX_TOKENS", "4096")),
    )

    return create_llm_client(config=config)
