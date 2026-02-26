"""Base LLM client abstraction and shared types.

Defines the abstract interface that all LLM client implementations
must follow, plus shared Pydantic models for configuration and
response handling.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from ziran.domain.entities.streaming import LLMResponseChunk

from pydantic import BaseModel, Field


class LLMConfig(BaseModel):
    """Configuration for the internal LLM backbone.

    Can be loaded from environment variables, CLI flags, or a
    YAML config file.
    """

    provider: str = Field(
        default="litellm",
        description="LLM provider: 'litellm' (recommended), 'openai', 'anthropic', 'bedrock'",
    )
    model: str = Field(
        default="gpt-4o",
        description="Model name (provider-specific, e.g. 'gpt-4o', 'claude-sonnet-4-20250514')",
    )
    api_key_env: str | None = Field(
        default=None,
        description="Environment variable containing the API key",
    )
    base_url: str | None = Field(
        default=None,
        description="Override base URL (for proxies or self-hosted models)",
    )
    temperature: float = Field(
        default=0.0,
        ge=0.0,
        le=2.0,
        description="Sampling temperature for LLM calls",
    )
    max_tokens: int = Field(
        default=4096,
        gt=0,
        description="Maximum tokens in the response",
    )


class LLMResponse(BaseModel):
    """Standardized response from an LLM call."""

    content: str = Field(description="The LLM's text response")
    model: str = Field(default="", description="Model that generated the response")
    prompt_tokens: int = Field(default=0, ge=0, description="Prompt tokens consumed")
    completion_tokens: int = Field(default=0, ge=0, description="Completion tokens consumed")
    total_tokens: int = Field(default=0, ge=0, description="Total tokens consumed")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Provider-specific metadata")


class BaseLLMClient(ABC):
    """Abstract base for internal LLM clients.

    Implementations wrap a specific LLM provider (OpenAI, Anthropic,
    Bedrock, LiteLLM) and expose a simple ``complete()`` interface.
    """

    def __init__(self, config: LLMConfig) -> None:
        self.config = config

    @abstractmethod
    async def complete(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> LLMResponse:
        """Send a chat completion request.

        Args:
            messages: List of message dicts with ``role`` and ``content``.
            temperature: Override default temperature for this call.
            max_tokens: Override default max_tokens for this call.
            **kwargs: Provider-specific parameters.

        Returns:
            Standardized LLM response.

        Raises:
            LLMError: On provider-level failures.
        """

    async def stream_complete(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[LLMResponseChunk]:
        """Stream a chat completion response chunk by chunk.

        Default implementation falls back to ``complete()`` and yields
        a single final chunk. Override in clients that support native
        streaming.

        Args:
            messages: List of message dicts with ``role`` and ``content``.
            temperature: Override default temperature for this call.
            max_tokens: Override default max_tokens for this call.
            **kwargs: Provider-specific parameters.

        Yields:
            Response chunks with incremental content.
        """
        from ziran.domain.entities.streaming import LLMResponseChunk

        response = await self.complete(
            messages, temperature=temperature, max_tokens=max_tokens, **kwargs
        )
        yield LLMResponseChunk(
            content_delta=response.content,
            is_final=True,
            model=response.model,
            metadata={
                "prompt_tokens": response.prompt_tokens,
                "completion_tokens": response.completion_tokens,
                "total_tokens": response.total_tokens,
                **response.metadata,
            },
        )

    @abstractmethod
    async def health_check(self) -> bool:
        """Verify that the LLM provider is reachable.

        Returns:
            True if the provider responds successfully.
        """


class LLMError(Exception):
    """Raised when an LLM call fails."""

    def __init__(self, message: str, *, provider: str = "", cause: Exception | None = None) -> None:
        super().__init__(message)
        self.provider = provider
        self.__cause__ = cause
