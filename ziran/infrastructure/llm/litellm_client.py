"""LiteLLM-based LLM client.

Wraps ``litellm.acompletion()`` to provide multi-vendor LLM support
via a single dependency. LiteLLM supports 100+ providers including
OpenAI, Anthropic, AWS Bedrock, Azure OpenAI, Ollama, Groq,
Mistral, Together AI, and many more.

Requires the ``llm`` extra::

    uv sync --extra llm
"""

from __future__ import annotations

import logging
import os
from typing import Any

from ziran.infrastructure.llm.base import BaseLLMClient, LLMConfig, LLMError, LLMResponse

logger = logging.getLogger(__name__)


def _import_litellm() -> Any:
    """Lazy-import litellm and return the module."""
    try:
        import litellm

        return litellm
    except ImportError as e:
        raise ImportError(
            "litellm is required for the LLM backbone. Install it with: uv sync --extra llm"
        ) from e


class LiteLLMClient(BaseLLMClient):
    """LLM client backed by LiteLLM.

    Delegates to ``litellm.acompletion()`` which routes to the
    appropriate provider based on the model name prefix:

    - ``gpt-*`` → OpenAI
    - ``claude-*`` → Anthropic
    - ``bedrock/...`` → AWS Bedrock
    - ``ollama/...`` → Ollama
    - ``azure/...`` → Azure OpenAI
    - etc.

    Example:
        ```python
        from ziran.infrastructure.llm.base import LLMConfig
        from ziran.infrastructure.llm.litellm_client import LiteLLMClient

        config = LLMConfig(model="claude-sonnet-4-20250514")
        client = LiteLLMClient(config)
        response = await client.complete([
            {"role": "user", "content": "Hello!"},
        ])
        ```
    """

    _api_key: str | None

    def __init__(self, config: LLMConfig) -> None:
        super().__init__(config)
        self._litellm = _import_litellm()

        # Set API key from env var if specified
        if config.api_key_env:
            api_key = os.environ.get(config.api_key_env, "")
            if api_key:
                self._api_key = api_key
            else:
                logger.warning(
                    "LLM API key env var '%s' is not set or empty",
                    config.api_key_env,
                )
                self._api_key = None
        else:
            self._api_key = None

        # Suppress litellm's verbose logging unless debug is on
        self._litellm.suppress_debug_info = True

    async def complete(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> LLMResponse:
        """Send a chat completion via LiteLLM.

        Args:
            messages: Chat messages.
            temperature: Override temperature.
            max_tokens: Override max_tokens.
            **kwargs: Additional params forwarded to litellm.acompletion().

        Returns:
            Standardized LLM response.

        Raises:
            LLMError: On provider failures.
        """
        call_kwargs: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": temperature if temperature is not None else self.config.temperature,
            "max_tokens": max_tokens if max_tokens is not None else self.config.max_tokens,
        }

        if self._api_key:
            call_kwargs["api_key"] = self._api_key
        if self.config.base_url:
            call_kwargs["api_base"] = self.config.base_url

        call_kwargs.update(kwargs)

        try:
            response = await self._litellm.acompletion(**call_kwargs)
        except Exception as exc:
            msg = f"LiteLLM call failed for model '{self.config.model}': {exc}"
            raise LLMError(msg, provider="litellm", cause=exc) from exc

        # Parse response (LiteLLM returns OpenAI-compatible ModelResponse)
        choice = response.choices[0]
        content = choice.message.content or ""
        usage = getattr(response, "usage", None)

        return LLMResponse(
            content=content,
            model=getattr(response, "model", self.config.model) or self.config.model,
            prompt_tokens=getattr(usage, "prompt_tokens", 0) if usage else 0,
            completion_tokens=getattr(usage, "completion_tokens", 0) if usage else 0,
            total_tokens=getattr(usage, "total_tokens", 0) if usage else 0,
            metadata={
                "provider": "litellm",
                "finish_reason": getattr(choice, "finish_reason", None),
            },
        )

    async def health_check(self) -> bool:
        """Check if the LLM provider is reachable via a minimal call."""
        try:
            await self.complete(
                [{"role": "user", "content": "ping"}],
                max_tokens=5,
            )
            return True
        except (LLMError, Exception):
            return False
