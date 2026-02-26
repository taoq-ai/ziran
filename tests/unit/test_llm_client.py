"""Unit tests for the LLM backbone: LLMConfig, factory, and LiteLLMClient."""

from __future__ import annotations

import os
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from ziran.infrastructure.llm.base import BaseLLMClient, LLMConfig, LLMError, LLMResponse

# ══════════════════════════════════════════════════════════════════════
# LLMConfig
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.unit
class TestLLMConfig:
    """Tests for LLMConfig Pydantic model."""

    def test_defaults(self) -> None:
        config = LLMConfig()
        assert config.provider == "litellm"
        assert config.model == "gpt-4o"
        assert config.api_key_env is None
        assert config.base_url is None
        assert config.temperature == 0.0
        assert config.max_tokens == 4096

    def test_custom_values(self) -> None:
        config = LLMConfig(
            provider="anthropic",
            model="claude-sonnet-4-20250514",
            api_key_env="ANTHROPIC_API_KEY",
            temperature=0.7,
            max_tokens=2048,
        )
        assert config.provider == "anthropic"
        assert config.model == "claude-sonnet-4-20250514"
        assert config.api_key_env == "ANTHROPIC_API_KEY"
        assert config.temperature == 0.7
        assert config.max_tokens == 2048

    def test_temperature_bounds(self) -> None:
        with pytest.raises(ValidationError):
            LLMConfig(temperature=-0.1)
        with pytest.raises(ValidationError):
            LLMConfig(temperature=2.1)

    def test_max_tokens_positive(self) -> None:
        with pytest.raises(ValidationError):
            LLMConfig(max_tokens=0)
        with pytest.raises(ValidationError):
            LLMConfig(max_tokens=-1)

    def test_base_url(self) -> None:
        config = LLMConfig(base_url="http://localhost:11434")
        assert config.base_url == "http://localhost:11434"


# ══════════════════════════════════════════════════════════════════════
# LLMResponse
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.unit
class TestLLMResponse:
    """Tests for LLMResponse model."""

    def test_minimal(self) -> None:
        r = LLMResponse(content="Hello!")
        assert r.content == "Hello!"
        assert r.model == ""
        assert r.prompt_tokens == 0
        assert r.total_tokens == 0
        assert r.metadata == {}

    def test_full(self) -> None:
        r = LLMResponse(
            content="Response",
            model="gpt-4o",
            prompt_tokens=10,
            completion_tokens=5,
            total_tokens=15,
            metadata={"finish_reason": "stop"},
        )
        assert r.model == "gpt-4o"
        assert r.total_tokens == 15


# ══════════════════════════════════════════════════════════════════════
# LLMError
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.unit
class TestLLMError:
    """Tests for LLMError exception."""

    def test_basic(self) -> None:
        err = LLMError("connection failed")
        assert str(err) == "connection failed"
        assert err.provider == ""

    def test_with_provider(self) -> None:
        cause = RuntimeError("timeout")
        err = LLMError("failed", provider="openai", cause=cause)
        assert err.provider == "openai"
        assert err.__cause__ is cause


# ══════════════════════════════════════════════════════════════════════
# create_llm_client factory
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.unit
class TestCreateLLMClient:
    """Tests for the create_llm_client factory function."""

    def test_creates_litellm_client_by_default(self) -> None:
        mock_litellm = MagicMock()
        with patch.dict("sys.modules", {"litellm": mock_litellm}):
            from ziran.infrastructure.llm.factory import create_llm_client

            client = create_llm_client(provider="litellm", model="gpt-4o")
            assert isinstance(client, BaseLLMClient)

    def test_openai_routes_to_litellm(self) -> None:
        mock_litellm = MagicMock()
        with patch.dict("sys.modules", {"litellm": mock_litellm}):
            from ziran.infrastructure.llm.factory import create_llm_client

            client = create_llm_client(provider="openai", model="gpt-4o")
            assert isinstance(client, BaseLLMClient)

    def test_anthropic_routes_to_litellm(self) -> None:
        mock_litellm = MagicMock()
        with patch.dict("sys.modules", {"litellm": mock_litellm}):
            from ziran.infrastructure.llm.factory import create_llm_client

            client = create_llm_client(provider="anthropic", model="claude-sonnet-4-20250514")
            assert isinstance(client, BaseLLMClient)

    def test_bedrock_routes_to_litellm(self) -> None:
        mock_litellm = MagicMock()
        with patch.dict("sys.modules", {"litellm": mock_litellm}):
            from ziran.infrastructure.llm.factory import create_llm_client

            client = create_llm_client(provider="bedrock", model="anthropic.claude-3")
            assert isinstance(client, BaseLLMClient)

    def test_unsupported_provider_raises(self) -> None:
        from ziran.infrastructure.llm.factory import create_llm_client

        with pytest.raises(ValueError, match="Unsupported LLM provider"):
            create_llm_client(provider="nonexistent", model="x")

    def test_config_overrides_params(self) -> None:
        mock_litellm = MagicMock()
        with patch.dict("sys.modules", {"litellm": mock_litellm}):
            from ziran.infrastructure.llm.factory import create_llm_client

            config = LLMConfig(provider="ollama", model="llama3.2", temperature=0.5)
            client = create_llm_client(
                provider="ignored",
                model="ignored",
                config=config,
            )
            assert client.config.model == "llama3.2"
            assert client.config.temperature == 0.5


@pytest.mark.unit
class TestCreateLLMClientFromEnv:
    """Tests for create_llm_client_from_env."""

    def test_returns_none_when_no_env(self) -> None:
        from ziran.infrastructure.llm.factory import create_llm_client_from_env

        with patch.dict(os.environ, {}, clear=True):
            # Ensure ZIRAN_LLM_* vars are not set
            for key in list(os.environ):
                if key.startswith("ZIRAN_LLM_"):
                    del os.environ[key]
            result = create_llm_client_from_env()
            assert result is None

    def test_creates_client_from_env(self) -> None:
        mock_litellm = MagicMock()
        with (
            patch.dict("sys.modules", {"litellm": mock_litellm}),
            patch.dict(
                os.environ,
                {
                    "ZIRAN_LLM_PROVIDER": "anthropic",
                    "ZIRAN_LLM_MODEL": "claude-sonnet-4-20250514",
                },
            ),
        ):
            from ziran.infrastructure.llm.factory import create_llm_client_from_env

            client = create_llm_client_from_env()
            assert client is not None
            assert client.config.provider == "anthropic"
            assert client.config.model == "claude-sonnet-4-20250514"


# ══════════════════════════════════════════════════════════════════════
# LiteLLMClient
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.unit
class TestLiteLLMClient:
    """Tests for the LiteLLM client wrapper."""

    @pytest.fixture
    def mock_litellm(self) -> MagicMock:
        mock = MagicMock()
        # Build a proper response object
        choice = MagicMock()
        choice.message.content = "Hello from LiteLLM!"
        choice.finish_reason = "stop"
        response = MagicMock()
        response.choices = [choice]
        response.model = "gpt-4o"
        response.usage.prompt_tokens = 10
        response.usage.completion_tokens = 5
        response.usage.total_tokens = 15
        mock.acompletion = AsyncMock(return_value=response)
        return mock

    @pytest.fixture
    def client(self, mock_litellm: MagicMock) -> Any:
        with patch.dict("sys.modules", {"litellm": mock_litellm}):
            from ziran.infrastructure.llm.litellm_client import LiteLLMClient

            config = LLMConfig(model="gpt-4o", temperature=0.0)
            c = LiteLLMClient(config)
        return c

    async def test_complete_returns_response(self, client: Any) -> None:
        response = await client.complete([{"role": "user", "content": "Hi"}])

        assert isinstance(response, LLMResponse)
        assert response.content == "Hello from LiteLLM!"
        assert response.model == "gpt-4o"
        assert response.prompt_tokens == 10
        assert response.total_tokens == 15

    async def test_complete_passes_params(self, client: Any) -> None:
        await client.complete(
            [{"role": "user", "content": "Test"}],
            temperature=0.5,
            max_tokens=100,
        )

        call_kwargs = client._litellm.acompletion.call_args[1]
        assert call_kwargs["temperature"] == 0.5
        assert call_kwargs["max_tokens"] == 100

    async def test_complete_uses_config_defaults(self, client: Any) -> None:
        await client.complete([{"role": "user", "content": "Test"}])

        call_kwargs = client._litellm.acompletion.call_args[1]
        assert call_kwargs["model"] == "gpt-4o"
        assert call_kwargs["temperature"] == 0.0
        assert call_kwargs["max_tokens"] == 4096

    async def test_complete_raises_llm_error(self, client: Any) -> None:
        client._litellm.acompletion.side_effect = Exception("API timeout")

        with pytest.raises(LLMError, match="LiteLLM call failed"):
            await client.complete([{"role": "user", "content": "Hi"}])

    async def test_health_check_success(self, client: Any) -> None:
        result = await client.health_check()
        assert result is True

    async def test_health_check_failure(self, client: Any) -> None:
        client._litellm.acompletion.side_effect = Exception("unreachable")
        result = await client.health_check()
        assert result is False

    def test_api_key_from_env(self, mock_litellm: MagicMock) -> None:
        with (
            patch.dict("sys.modules", {"litellm": mock_litellm}),
            patch.dict(os.environ, {"MY_API_KEY": "sk-test-123"}),
        ):
            from ziran.infrastructure.llm.litellm_client import LiteLLMClient

            config = LLMConfig(model="gpt-4o", api_key_env="MY_API_KEY")
            c = LiteLLMClient(config)
            assert c._api_key == "sk-test-123"

    def test_base_url_stored(self, mock_litellm: MagicMock) -> None:
        with patch.dict("sys.modules", {"litellm": mock_litellm}):
            from ziran.infrastructure.llm.litellm_client import LiteLLMClient

            config = LLMConfig(model="llama3", base_url="http://localhost:11434")
            c = LiteLLMClient(config)
            assert c.config.base_url == "http://localhost:11434"


@pytest.mark.unit
class TestLiteLLMImportGuard:
    """Tests for litellm import error handling."""

    def test_import_error_without_litellm(self) -> None:
        with patch.dict("sys.modules", {"litellm": None}):
            from ziran.infrastructure.llm.litellm_client import _import_litellm

            with pytest.raises(ImportError, match="litellm is required"):
                _import_litellm()


# ──────────────────────────────────────────────────────────────────────
# LiteLLMClient health_check & empty api_key
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestLiteLLMClientExtras:
    def test_empty_api_key_env_warning(self) -> None:
        """When api_key_env is set but env var is empty, _api_key should be None."""
        cfg = LLMConfig(model="gpt-4", api_key_env="EMPTY_KEY_FOR_TEST")

        with (
            patch.dict("os.environ", {"EMPTY_KEY_FOR_TEST": ""}),
            patch("ziran.infrastructure.llm.litellm_client._import_litellm") as m,
        ):
            m.return_value = MagicMock()

            from ziran.infrastructure.llm.litellm_client import LiteLLMClient

            client = LiteLLMClient(cfg)
            assert client._api_key is None

    async def test_health_check_success(self) -> None:
        cfg = LLMConfig(model="gpt-4")

        with patch("ziran.infrastructure.llm.litellm_client._import_litellm") as m:
            m.return_value = MagicMock()

            from ziran.infrastructure.llm.litellm_client import LiteLLMClient

            client = LiteLLMClient(cfg)
            client.complete = AsyncMock(return_value=MagicMock(content="pong"))
            result = await client.health_check()
            assert result is True

    async def test_health_check_failure(self) -> None:
        cfg = LLMConfig(model="gpt-4")

        with patch("ziran.infrastructure.llm.litellm_client._import_litellm") as m:
            m.return_value = MagicMock()

            from ziran.infrastructure.llm.litellm_client import LiteLLMClient

            client = LiteLLMClient(cfg)
            client.complete = AsyncMock(side_effect=LLMError("fail", provider="test"))
            result = await client.health_check()
            assert result is False
