"""Unit tests for target configuration models and protocol entities."""

from __future__ import annotations

import os
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from ziran.domain.entities.target import (
    A2AConfig,
    AuthConfig,
    AuthType,
    OpenAIConfig,
    ProtocolType,
    RestConfig,
    RetryConfig,
    TargetConfig,
    TargetConfigError,
    TlsConfig,
    load_target_config,
)

# ──────────────────────────────────────────────────────────────────────
# ProtocolType enum
# ──────────────────────────────────────────────────────────────────────


class TestProtocolType:
    """Tests for the ProtocolType enum."""

    def test_all_values(self) -> None:
        assert ProtocolType.REST == "rest"
        assert ProtocolType.OPENAI == "openai"
        assert ProtocolType.MCP == "mcp"
        assert ProtocolType.A2A == "a2a"
        assert ProtocolType.AUTO == "auto"

    def test_from_string(self) -> None:
        assert ProtocolType("a2a") == ProtocolType.A2A

    def test_invalid_raises(self) -> None:
        with pytest.raises(ValueError):
            ProtocolType("graphql")


# ──────────────────────────────────────────────────────────────────────
# AuthConfig
# ──────────────────────────────────────────────────────────────────────


class TestAuthConfig:
    """Tests for authentication configuration."""

    def test_bearer_with_token(self) -> None:
        auth = AuthConfig(type=AuthType.BEARER, token="sk-test-123")
        assert auth.get_resolved_token() == "sk-test-123"

    def test_bearer_with_env_var(self) -> None:
        auth = AuthConfig(type=AuthType.BEARER, env_var="TEST_TOKEN")
        with patch.dict(os.environ, {"TEST_TOKEN": "env-value"}):
            assert auth.get_resolved_token() == "env-value"

    def test_bearer_missing_token_raises(self) -> None:
        auth = AuthConfig(type=AuthType.BEARER)
        with pytest.raises(ValueError, match="No token"):
            auth.get_resolved_token()

    def test_api_key_custom_header(self) -> None:
        auth = AuthConfig(
            type=AuthType.API_KEY,
            token="key-abc",
            header_name="X-Custom-Key",
        )
        assert auth.header_name == "X-Custom-Key"
        assert auth.get_resolved_token() == "key-abc"

    def test_basic_auth(self) -> None:
        auth = AuthConfig(
            type=AuthType.BASIC,
            username="user",
            password="pass",
        )
        assert auth.username == "user"
        assert auth.password == "pass"

    def test_oauth2_fields(self) -> None:
        auth = AuthConfig(
            type=AuthType.OAUTH2,
            client_id="cid",
            client_secret="csecret",
            token_url="https://auth.example.com/token",
            scopes=["read", "write"],
        )
        assert auth.type == AuthType.OAUTH2
        assert auth.scopes == ["read", "write"]


# ──────────────────────────────────────────────────────────────────────
# TlsConfig
# ──────────────────────────────────────────────────────────────────────


class TestTlsConfig:
    """Tests for TLS configuration."""

    def test_defaults(self) -> None:
        tls = TlsConfig()
        assert tls.verify is True
        assert tls.client_cert is None
        assert tls.client_key is None

    def test_disable_verification(self) -> None:
        tls = TlsConfig(verify=False)
        assert tls.verify is False


# ──────────────────────────────────────────────────────────────────────
# RetryConfig
# ──────────────────────────────────────────────────────────────────────


class TestRetryConfig:
    """Tests for retry configuration."""

    def test_defaults(self) -> None:
        retry = RetryConfig()
        assert retry.max_retries == 3
        assert retry.backoff_factor == 0.5
        assert 429 in retry.retry_on
        assert 503 in retry.retry_on

    def test_custom_values(self) -> None:
        retry = RetryConfig(max_retries=5, backoff_factor=1.0, retry_on=[500])
        assert retry.max_retries == 5
        assert retry.retry_on == [500]


# ──────────────────────────────────────────────────────────────────────
# RestConfig
# ──────────────────────────────────────────────────────────────────────


class TestRestConfig:
    """Tests for REST-specific configuration."""

    def test_defaults(self) -> None:
        rest = RestConfig()
        assert rest.method == "POST"
        assert rest.message_field == "message"
        assert rest.response_field == "response"

    def test_custom(self) -> None:
        rest = RestConfig(
            method="PUT",
            request_path="/api/v2/chat",
            message_field="input.text",
            response_field="output.message",
        )
        assert rest.method == "PUT"
        assert rest.request_path == "/api/v2/chat"


# ──────────────────────────────────────────────────────────────────────
# A2AConfig
# ──────────────────────────────────────────────────────────────────────


class TestA2AConfig:
    """Tests for A2A-specific configuration."""

    def test_defaults(self) -> None:
        a2a = A2AConfig()
        assert a2a.protocol_binding == "HTTP+JSON"
        assert a2a.a2a_version == "1.0"
        assert a2a.blocking is True
        assert a2a.use_extended_card is False
        assert a2a.enable_streaming is False

    def test_custom(self) -> None:
        a2a = A2AConfig(
            agent_card_url="https://example.com/card.json",
            protocol_binding="JSONRPC",
            blocking=False,
        )
        assert a2a.agent_card_url == "https://example.com/card.json"
        assert a2a.protocol_binding == "JSONRPC"
        assert a2a.blocking is False


# ──────────────────────────────────────────────────────────────────────
# TargetConfig
# ──────────────────────────────────────────────────────────────────────


class TestTargetConfig:
    """Tests for the main target configuration."""

    def test_minimal(self) -> None:
        config = TargetConfig(url="https://agent.example.com")
        assert config.url == "https://agent.example.com"
        assert config.protocol == ProtocolType.AUTO
        assert config.timeout == 30.0

    def test_normalized_url(self) -> None:
        config = TargetConfig(url="https://agent.example.com/")
        assert config.normalized_url == "https://agent.example.com"

    def test_full_config(self) -> None:
        config = TargetConfig(
            url="https://agent.example.com",
            protocol=ProtocolType.A2A,
            auth=AuthConfig(type=AuthType.BEARER, token="tok"),
            tls=TlsConfig(verify=False),
            retry=RetryConfig(max_retries=5),
            timeout=60.0,
            headers={"X-Custom": "value"},
            proxy="http://proxy:8080",
        )
        assert config.protocol == ProtocolType.A2A
        assert config.auth is not None
        assert config.auth.token == "tok"
        assert config.tls.verify is False
        assert config.retry.max_retries == 5
        assert config.timeout == 60.0
        assert config.headers["X-Custom"] == "value"
        assert config.proxy == "http://proxy:8080"


# ──────────────────────────────────────────────────────────────────────
# load_target_config
# ──────────────────────────────────────────────────────────────────────


class TestLoadTargetConfig:
    """Tests for YAML config loading."""

    def test_load_valid_yaml(self, tmp_path: Path) -> None:
        yaml_content = textwrap.dedent("""\
            url: https://agent.example.com
            protocol: openai
            timeout: 45.0
            auth:
              type: bearer
              token: sk-test
        """)
        config_file = tmp_path / "target.yaml"
        config_file.write_text(yaml_content)

        config = load_target_config(config_file)
        assert config.url == "https://agent.example.com"
        assert config.protocol == ProtocolType.OPENAI
        assert config.timeout == 45.0
        assert config.auth is not None
        assert config.auth.token == "sk-test"

    def test_load_minimal_yaml(self, tmp_path: Path) -> None:
        yaml_content = "url: https://agent.example.com\n"
        config_file = tmp_path / "target.yaml"
        config_file.write_text(yaml_content)

        config = load_target_config(config_file)
        assert config.url == "https://agent.example.com"
        assert config.protocol == ProtocolType.AUTO

    def test_load_a2a_config(self, tmp_path: Path) -> None:
        yaml_content = textwrap.dedent("""\
            url: https://a2a-agent.example.com
            protocol: a2a
            a2a:
              blocking: false
              use_extended_card: true
        """)
        config_file = tmp_path / "target.yaml"
        config_file.write_text(yaml_content)

        config = load_target_config(config_file)
        assert config.protocol == ProtocolType.A2A
        assert config.a2a.blocking is False
        assert config.a2a.use_extended_card is True

    def test_load_nonexistent_raises(self) -> None:
        with pytest.raises(TargetConfigError, match="not found"):
            load_target_config(Path("/nonexistent/path.yaml"))

    def test_load_invalid_yaml(self, tmp_path: Path) -> None:
        config_file = tmp_path / "bad.yaml"
        config_file.write_text("not: [valid: yaml: {{}")

        with pytest.raises(TargetConfigError):
            load_target_config(config_file)


# ──────────────────────────────────────────────────────────────────────
# OpenAIConfig
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestOpenAIConfig:
    """Tests for the OpenAI-compatible protocol configuration."""

    def test_defaults(self) -> None:
        config = OpenAIConfig()
        assert config.model == "gpt-4"
        assert config.temperature is None
        assert config.max_tokens is None

    def test_custom_values(self) -> None:
        config = OpenAIConfig(model="gpt-4o", temperature=0.5, max_tokens=2048)
        assert config.model == "gpt-4o"
        assert config.temperature == 0.5
        assert config.max_tokens == 2048

    def test_temperature_bounds(self) -> None:
        OpenAIConfig(temperature=0.0)  # OK
        OpenAIConfig(temperature=2.0)  # OK
        with pytest.raises(ValidationError):
            OpenAIConfig(temperature=-0.1)
        with pytest.raises(ValidationError):
            OpenAIConfig(temperature=2.1)

    def test_max_tokens_positive(self) -> None:
        OpenAIConfig(max_tokens=1)  # OK
        with pytest.raises(ValidationError):
            OpenAIConfig(max_tokens=0)
        with pytest.raises(ValidationError):
            OpenAIConfig(max_tokens=-1)


@pytest.mark.unit
class TestTargetConfigOpenAI:
    """Tests for TargetConfig with OpenAI protocol."""

    def test_openai_protocol_auto_creates_config(self) -> None:
        config = TargetConfig(url="https://api.openai.com", protocol=ProtocolType.OPENAI)
        assert config.openai is not None
        assert config.openai.model == "gpt-4"

    def test_openai_protocol_preserves_custom_config(self) -> None:
        config = TargetConfig(
            url="https://api.openai.com",
            protocol=ProtocolType.OPENAI,
            openai=OpenAIConfig(model="gpt-4o", temperature=0.7, max_tokens=1024),
        )
        assert config.openai is not None
        assert config.openai.model == "gpt-4o"
        assert config.openai.temperature == 0.7
        assert config.openai.max_tokens == 1024

    def test_non_openai_protocol_no_auto_config(self) -> None:
        config = TargetConfig(url="https://agent.example.com", protocol=ProtocolType.REST)
        assert config.openai is None

    def test_load_openai_yaml(self, tmp_path: Path) -> None:
        yaml_content = textwrap.dedent("""\
            url: https://api.openai.com
            protocol: openai
            openai:
              model: gpt-4o
              temperature: 0.3
              max_tokens: 2048
        """)
        config_file = tmp_path / "target.yaml"
        config_file.write_text(yaml_content)

        config = load_target_config(config_file)
        assert config.protocol == ProtocolType.OPENAI
        assert config.openai is not None
        assert config.openai.model == "gpt-4o"
        assert config.openai.temperature == 0.3
        assert config.openai.max_tokens == 2048

    def test_load_openai_yaml_minimal(self, tmp_path: Path) -> None:
        """OpenAI protocol without explicit config auto-creates defaults."""
        yaml_content = textwrap.dedent("""\
            url: https://api.openai.com
            protocol: openai
        """)
        config_file = tmp_path / "target.yaml"
        config_file.write_text(yaml_content)

        config = load_target_config(config_file)
        assert config.openai is not None
        assert config.openai.model == "gpt-4"
