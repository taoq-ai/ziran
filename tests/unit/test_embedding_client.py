"""LiteLLM embedding adapter and graceful absence of the llm extra (spec 042, FR-002/FR-003)."""

from __future__ import annotations

import logging
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ziran.application.detectors.semantic import SemanticConfig
from ziran.infrastructure.llm.base import LLMError
from ziran.infrastructure.llm.embedding import LiteLLMEmbedder, create_embedder

pytestmark = pytest.mark.unit

_PATCH = "ziran.infrastructure.llm.litellm_client._import_litellm"


def _fake_litellm(vectors: list[list[float]] | None = None) -> MagicMock:
    fake = MagicMock()
    data = [{"embedding": v} for v in (vectors or [[1.0, 2.0], [3.0, 4.0]])]
    fake.aembedding = AsyncMock(return_value=SimpleNamespace(data=data))
    return fake


async def test_embed_passes_model_input_and_base(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _fake_litellm()
    with patch(_PATCH, return_value=fake):
        emb = LiteLLMEmbedder("ollama/nomic-embed-text", base_url="http://localhost:11434")
    out = await emb.embed(["a", "b"])
    assert out == [[1.0, 2.0], [3.0, 4.0]]
    kwargs = fake.aembedding.call_args.kwargs
    assert kwargs["model"] == "ollama/nomic-embed-text"
    assert kwargs["input"] == ["a", "b"]
    assert kwargs["api_base"] == "http://localhost:11434"
    assert "api_key" not in kwargs


async def test_api_key_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ZIRAN_TEST_EMBED_KEY", "k-123")
    fake = _fake_litellm()
    with patch(_PATCH, return_value=fake):
        emb = LiteLLMEmbedder("m", api_key_env="ZIRAN_TEST_EMBED_KEY")
    await emb.embed(["a", "b"])
    assert fake.aembedding.call_args.kwargs["api_key"] == "k-123"
    assert "api_base" not in fake.aembedding.call_args.kwargs


async def test_empty_api_key_env_warns(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("ZIRAN_TEST_EMBED_KEY", "")
    fake = _fake_litellm()
    with caplog.at_level(logging.WARNING), patch(_PATCH, return_value=fake):
        emb = LiteLLMEmbedder("m", api_key_env="ZIRAN_TEST_EMBED_KEY")
    assert "semantic.api_key_env" in caplog.text
    await emb.embed(["a", "b"])
    assert "api_key" not in fake.aembedding.call_args.kwargs


async def test_empty_input_skips_provider() -> None:
    fake = _fake_litellm()
    with patch(_PATCH, return_value=fake):
        emb = LiteLLMEmbedder("m")
    assert await emb.embed([]) == []
    fake.aembedding.assert_not_called()


async def test_provider_error_wrapped_with_type_only() -> None:
    fake = MagicMock()
    fake.aembedding = AsyncMock(side_effect=RuntimeError("echoed secret text"))
    with patch(_PATCH, return_value=fake):
        emb = LiteLLMEmbedder("m")
    with pytest.raises(LLMError) as exc:
        await emb.embed(["a"])
    assert str(exc.value) == "embedding call failed: RuntimeError"


async def test_count_mismatch_raises() -> None:
    with patch(_PATCH, return_value=_fake_litellm([[1.0]])):
        emb = LiteLLMEmbedder("m")
    with pytest.raises(LLMError):
        await emb.embed(["a", "b"])


def test_create_embedder(caplog: pytest.LogCaptureFixture) -> None:
    with patch(_PATCH) as imp:
        assert create_embedder(SemanticConfig()) is None
        imp.assert_not_called()
    with patch(_PATCH, return_value=_fake_litellm()):
        assert isinstance(create_embedder(SemanticConfig(enabled=True)), LiteLLMEmbedder)
    with caplog.at_level(logging.WARNING), patch(_PATCH, side_effect=ImportError("no litellm")):
        assert create_embedder(SemanticConfig(enabled=True)) is None
    assert caplog.text.count("uv sync --extra llm") == 1


def test_modules_import_without_litellm() -> None:
    # Fresh interpreter so the blocked import cannot leak into other tests.
    code = (
        "import sys; sys.modules['litellm'] = None; "
        "import ziran.application.detectors.pipeline, ziran.infrastructure.llm.embedding"
    )
    subprocess.run([sys.executable, "-c", code], check=True)
