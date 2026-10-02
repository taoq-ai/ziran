"""LiteLLM-backed text embeddings for the semantic detection tier (spec 042).

Uses ``litellm.aembedding`` from the existing ``llm`` extra::

    uv sync --extra llm
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

from ziran.domain.interfaces.embedder import BaseEmbedder
from ziran.infrastructure.llm import litellm_client
from ziran.infrastructure.llm.base import LLMError

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ziran.application.detectors.semantic import SemanticConfig

logger = logging.getLogger(__name__)


class LiteLLMEmbedder(BaseEmbedder):
    """Embedding provider routed through litellm (``ollama/...``, ``text-embedding-3-small``...)."""

    def __init__(
        self, model: str, *, base_url: str | None = None, api_key_env: str | None = None
    ) -> None:
        """Raises ImportError when the ``llm`` extra is absent."""
        self._litellm = litellm_client._import_litellm()
        self._model = model
        self._base_url = base_url
        self._api_key: str | None = None
        if api_key_env:
            self._api_key = os.environ.get(api_key_env) or None
            if self._api_key is None:
                logger.warning(f"Embedding API key env var {api_key_env!r} is not set or empty")

    async def embed(self, texts: Sequence[str]) -> list[list[float]]:
        if not texts:
            return []
        kwargs: dict[str, Any] = {"model": self._model, "input": list(texts)}
        if self._base_url:
            kwargs["api_base"] = self._base_url
        if self._api_key:
            kwargs["api_key"] = self._api_key
        try:
            response = await self._litellm.aembedding(**kwargs)
        except Exception as exc:
            # Type only: provider messages may echo the input text.
            raise LLMError(
                f"embedding call failed: {type(exc).__name__}", provider="litellm", cause=exc
            ) from exc
        vectors = [[float(x) for x in item["embedding"]] for item in response.data]
        if len(vectors) != len(texts):
            raise LLMError("embedding count mismatch", provider="litellm")
        return vectors


def create_embedder(config: SemanticConfig) -> BaseEmbedder | None:
    """Embedder for *config*, or ``None`` when disabled or litellm is not installed."""
    if not config.enabled:
        return None
    try:
        return LiteLLMEmbedder(
            config.model, base_url=config.base_url, api_key_env=config.api_key_env
        )
    except ImportError:
        logger.warning("semantic tier disabled: litellm not installed. Run: uv sync --extra llm")
        return None
