"""Unit tests for LiteLLMClient."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ziran.infrastructure.llm.base import LLMConfig, LLMError

# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _make_mock_litellm() -> MagicMock:
    """Return a mock litellm module."""
    mod = MagicMock()
    mod.suppress_debug_info = True
    return mod


def _make_response(
    content: str = "Hello!",
    *,
    model: str = "gpt-4",
    prompt_tokens: int = 10,
    completion_tokens: int = 5,
    total_tokens: int = 15,
    finish_reason: str = "stop",
) -> MagicMock:
    """Build a mock litellm ModelResponse."""
    resp = MagicMock()
    choice = MagicMock()
    choice.message.content = content
    choice.finish_reason = finish_reason
    resp.choices = [choice]
    resp.model = model

    usage = MagicMock()
    usage.prompt_tokens = prompt_tokens
    usage.completion_tokens = completion_tokens
    usage.total_tokens = total_tokens
    resp.usage = usage

    return resp


# ──────────────────────────────────────────────────────────────────────
# Init
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestLiteLLMInit:
    """Tests for LiteLLMClient initialization."""

    def test_init_default(self) -> None:
        with patch(
            "ziran.infrastructure.llm.litellm_client._import_litellm",
            return_value=_make_mock_litellm(),
        ):
            from ziran.infrastructure.llm.litellm_client import LiteLLMClient

            config = LLMConfig(model="gpt-4")
            client = LiteLLMClient(config)
            assert client.config.model == "gpt-4"
            assert client._api_key is None

    def test_api_key_from_env(self) -> None:
        with (
            patch(
                "ziran.infrastructure.llm.litellm_client._import_litellm",
                return_value=_make_mock_litellm(),
            ),
            patch.dict(os.environ, {"MY_KEY": "sk-test123"}),
        ):
            from ziran.infrastructure.llm.litellm_client import LiteLLMClient

            config = LLMConfig(model="gpt-4", api_key_env="MY_KEY")
            client = LiteLLMClient(config)
            assert client._api_key == "sk-test123"

    def test_missing_api_key_env(self) -> None:
        with (
            patch(
                "ziran.infrastructure.llm.litellm_client._import_litellm",
                return_value=_make_mock_litellm(),
            ),
            patch.dict(os.environ, {}, clear=True),
        ):
            from ziran.infrastructure.llm.litellm_client import LiteLLMClient

            config = LLMConfig(model="gpt-4", api_key_env="MISSING_KEY")
            client = LiteLLMClient(config)
            assert client._api_key is None


# ──────────────────────────────────────────────────────────────────────
# complete
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestLiteLLMComplete:
    """Tests for LiteLLMClient.complete."""

    async def test_basic_completion(self) -> None:
        mock_litellm = _make_mock_litellm()
        mock_litellm.acompletion = AsyncMock(return_value=_make_response("Test reply"))

        with patch(
            "ziran.infrastructure.llm.litellm_client._import_litellm", return_value=mock_litellm
        ):
            from ziran.infrastructure.llm.litellm_client import LiteLLMClient

            config = LLMConfig(model="gpt-4")
            client = LiteLLMClient(config)

            result = await client.complete([{"role": "user", "content": "Hi"}])

            assert result.content == "Test reply"
            assert result.model == "gpt-4"
            assert result.prompt_tokens == 10
            assert result.total_tokens == 15

    async def test_completion_with_temperature(self) -> None:
        mock_litellm = _make_mock_litellm()
        mock_litellm.acompletion = AsyncMock(return_value=_make_response())

        with patch(
            "ziran.infrastructure.llm.litellm_client._import_litellm", return_value=mock_litellm
        ):
            from ziran.infrastructure.llm.litellm_client import LiteLLMClient

            config = LLMConfig(model="gpt-4")
            client = LiteLLMClient(config)

            await client.complete([{"role": "user", "content": "Hi"}], temperature=0.7)

            call_kwargs = mock_litellm.acompletion.call_args[1]
            assert call_kwargs["temperature"] == 0.7

    async def test_completion_with_api_key_and_base_url(self) -> None:
        mock_litellm = _make_mock_litellm()
        mock_litellm.acompletion = AsyncMock(return_value=_make_response())

        with (
            patch(
                "ziran.infrastructure.llm.litellm_client._import_litellm", return_value=mock_litellm
            ),
            patch.dict(os.environ, {"KEY": "sk-abc"}),
        ):
            from ziran.infrastructure.llm.litellm_client import LiteLLMClient

            config = LLMConfig(
                model="gpt-4",
                api_key_env="KEY",
                base_url="https://custom.api.com",
            )
            client = LiteLLMClient(config)

            await client.complete([{"role": "user", "content": "Hi"}])

            call_kwargs = mock_litellm.acompletion.call_args[1]
            assert call_kwargs["api_key"] == "sk-abc"
            assert call_kwargs["api_base"] == "https://custom.api.com"

    async def test_completion_error_raises_llm_error(self) -> None:
        mock_litellm = _make_mock_litellm()
        mock_litellm.acompletion = AsyncMock(side_effect=RuntimeError("API down"))

        with patch(
            "ziran.infrastructure.llm.litellm_client._import_litellm", return_value=mock_litellm
        ):
            from ziran.infrastructure.llm.litellm_client import LiteLLMClient

            config = LLMConfig(model="gpt-4")
            client = LiteLLMClient(config)

            with pytest.raises(LLMError, match="LiteLLM call failed"):
                await client.complete([{"role": "user", "content": "Hi"}])


# ──────────────────────────────────────────────────────────────────────
# health_check
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestLiteLLMHealthCheck:
    """Tests for LiteLLMClient.health_check."""

    async def test_healthy(self) -> None:
        mock_litellm = _make_mock_litellm()
        mock_litellm.acompletion = AsyncMock(return_value=_make_response("pong"))

        with patch(
            "ziran.infrastructure.llm.litellm_client._import_litellm", return_value=mock_litellm
        ):
            from ziran.infrastructure.llm.litellm_client import LiteLLMClient

            client = LiteLLMClient(LLMConfig(model="gpt-4"))
            assert await client.health_check() is True

    async def test_unhealthy(self) -> None:
        mock_litellm = _make_mock_litellm()
        mock_litellm.acompletion = AsyncMock(side_effect=RuntimeError("timeout"))

        with patch(
            "ziran.infrastructure.llm.litellm_client._import_litellm", return_value=mock_litellm
        ):
            from ziran.infrastructure.llm.litellm_client import LiteLLMClient

            client = LiteLLMClient(LLMConfig(model="gpt-4"))
            assert await client.health_check() is False


# ──────────────────────────────────────────────────────────────────────
# stream_complete
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestLiteLLMStreamComplete:
    """Tests for LiteLLMClient.stream_complete."""

    async def test_stream_yields_chunks(self) -> None:
        mock_litellm = _make_mock_litellm()

        # Build async iterator for streaming response
        chunk1 = MagicMock()
        delta1 = MagicMock()
        delta1.content = "Hello"
        choice1 = MagicMock()
        choice1.delta = delta1
        choice1.finish_reason = None
        chunk1.choices = [choice1]
        chunk1.model = "gpt-4"

        chunk2 = MagicMock()
        delta2 = MagicMock()
        delta2.content = " world"
        choice2 = MagicMock()
        choice2.delta = delta2
        choice2.finish_reason = "stop"
        chunk2.choices = [choice2]
        chunk2.model = "gpt-4"

        async def _fake_stream():
            yield chunk1
            yield chunk2

        mock_litellm.acompletion = AsyncMock(return_value=_fake_stream())

        with patch(
            "ziran.infrastructure.llm.litellm_client._import_litellm", return_value=mock_litellm
        ):
            from ziran.infrastructure.llm.litellm_client import LiteLLMClient

            client = LiteLLMClient(LLMConfig(model="gpt-4"))
            chunks = []
            async for c in client.stream_complete([{"role": "user", "content": "Hi"}]):
                chunks.append(c)

            assert len(chunks) == 2
            assert chunks[0].content_delta == "Hello"
            assert chunks[0].is_final is False
            assert chunks[1].content_delta == " world"
            assert chunks[1].is_final is True

    async def test_stream_empty_chunks_skipped(self) -> None:
        mock_litellm = _make_mock_litellm()

        # A chunk with no choices
        empty_chunk = MagicMock()
        empty_chunk.choices = []

        content_chunk = MagicMock()
        delta = MagicMock()
        delta.content = "OK"
        choice = MagicMock()
        choice.delta = delta
        choice.finish_reason = "stop"
        content_chunk.choices = [choice]
        content_chunk.model = "gpt-4"

        async def _fake_stream():
            yield empty_chunk
            yield content_chunk

        mock_litellm.acompletion = AsyncMock(return_value=_fake_stream())

        with patch(
            "ziran.infrastructure.llm.litellm_client._import_litellm", return_value=mock_litellm
        ):
            from ziran.infrastructure.llm.litellm_client import LiteLLMClient

            client = LiteLLMClient(LLMConfig(model="gpt-4"))
            chunks = []
            async for c in client.stream_complete([{"role": "user", "content": "test"}]):
                chunks.append(c)

            assert len(chunks) == 1
            assert chunks[0].content_delta == "OK"

    async def test_stream_error_raises_llm_error(self) -> None:
        mock_litellm = _make_mock_litellm()
        mock_litellm.acompletion = AsyncMock(side_effect=RuntimeError("stream failed"))

        with patch(
            "ziran.infrastructure.llm.litellm_client._import_litellm", return_value=mock_litellm
        ):
            from ziran.infrastructure.llm.litellm_client import LiteLLMClient

            client = LiteLLMClient(LLMConfig(model="gpt-4"))
            with pytest.raises(LLMError, match="LiteLLM streaming call failed"):
                async for _ in client.stream_complete([{"role": "user", "content": "Hi"}]):
                    pass

    async def test_stream_with_api_key(self) -> None:
        mock_litellm = _make_mock_litellm()

        async def _empty_stream():
            return
            yield  # make it a generator

        mock_litellm.acompletion = AsyncMock(return_value=_empty_stream())

        with (
            patch(
                "ziran.infrastructure.llm.litellm_client._import_litellm", return_value=mock_litellm
            ),
            patch.dict(os.environ, {"KEY": "sk-xyz"}),
        ):
            from ziran.infrastructure.llm.litellm_client import LiteLLMClient

            client = LiteLLMClient(LLMConfig(model="gpt-4", api_key_env="KEY"))
            async for _ in client.stream_complete([{"role": "user", "content": "Hi"}]):
                pass

            call_kwargs = mock_litellm.acompletion.call_args[1]
            assert call_kwargs["stream"] is True
            assert call_kwargs["api_key"] == "sk-xyz"
