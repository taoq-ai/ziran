"""Target configuration models for remote agent scanning.

Defines the YAML-driven configuration schema for scanning agents
published over HTTPS. Supports multiple protocols (REST, OpenAI-compatible,
MCP, A2A) with enterprise features (auth, TLS, retries, proxy).
"""

from __future__ import annotations

import os
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Literal

import yaml
from pydantic import BaseModel, Field, model_validator

if TYPE_CHECKING:
    from pathlib import Path


class ProtocolType(StrEnum):
    """Supported remote agent protocol types."""

    REST = "rest"
    """Generic REST API — configurable request/response JSON paths."""

    OPENAI = "openai"
    """OpenAI-compatible chat completions API."""

    MCP = "mcp"
    """Model Context Protocol — JSON-RPC 2.0 tool server."""

    A2A = "a2a"
    """Agent-to-Agent Protocol — Agent Card discovery + task-based messaging."""

    AUTO = "auto"
    """Auto-detect: try A2A Agent Card → OpenAI /v1/models → generic REST."""


class AuthType(StrEnum):
    """Supported authentication types."""

    BEARER = "bearer"
    API_KEY = "api_key"
    BASIC = "basic"
    OAUTH2 = "oauth2"


class AuthConfig(BaseModel):
    """Authentication configuration for remote agent endpoints.

    Credentials can be provided inline or resolved from environment
    variables via ``env_var``.
    """

    type: AuthType

    # Bearer / API key
    token: str | None = Field(default=None, description="Bearer token or API key value")
    env_var: str | None = Field(
        default=None, description="Environment variable to resolve token from"
    )

    # API key specifics
    header_name: str = Field(
        default="Authorization",
        description="Header name for API key (e.g. 'X-API-KEY')",
    )

    # Basic auth
    username: str | None = None
    password: str | None = None

    # OAuth2 client credentials
    client_id: str | None = None
    client_secret: str | None = None
    token_url: str | None = None
    scopes: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _resolve_env_var(self) -> AuthConfig:
        """Resolve token from environment variable if specified."""
        if self.env_var and not self.token:
            self.token = os.environ.get(self.env_var, "")
        return self

    def get_resolved_token(self) -> str:
        """Return the resolved token value.

        Returns:
            The token string, resolved from env_var if needed.

        Raises:
            ValueError: If no token could be resolved.
        """
        if self.token:
            return self.token
        if self.env_var:
            value = os.environ.get(self.env_var, "")
            if value:
                return value
        msg = f"No token resolved for auth type '{self.type}'"
        raise ValueError(msg)


class TlsConfig(BaseModel):
    """TLS configuration for secure connections.

    Supports custom CA certificates and mutual TLS (mTLS).
    """

    verify: bool | str = Field(
        default=True,
        description="True for default CA, False to disable, or path to custom CA bundle",
    )
    client_cert: str | None = Field(default=None, description="Path to client certificate for mTLS")
    client_key: str | None = Field(default=None, description="Path to client private key for mTLS")


class RetryConfig(BaseModel):
    """Retry configuration for transient failures."""

    max_retries: int = Field(default=3, ge=0, le=10, description="Maximum retry attempts")
    backoff_factor: float = Field(
        default=0.5, ge=0.0, le=30.0, description="Exponential backoff multiplier in seconds"
    )
    retry_on: list[int] = Field(
        default_factory=lambda: [429, 500, 502, 503, 504],
        description="HTTP status codes to retry on",
    )


class RestConfig(BaseModel):
    """Configuration specific to generic REST protocol."""

    method: Literal["POST", "GET", "PUT"] = Field(
        default="POST", description="HTTP method for sending messages"
    )
    request_path: str = Field(
        default="", description="URL path appended to base URL (e.g. '/chat')"
    )
    message_field: str = Field(
        default="message", description="JSON field name for the input message"
    )
    response_field: str = Field(
        default="response", description="JSON field name to extract the response from"
    )
    extra_body: dict[str, Any] = Field(
        default_factory=dict, description="Extra fields to include in the request body"
    )


class OpenAIConfig(BaseModel):
    """Configuration specific to the OpenAI-compatible protocol.

    Allows overriding the model name, temperature, and max_tokens
    sent to any OpenAI-compatible endpoint (OpenAI, Azure OpenAI,
    vLLM, Ollama, LiteLLM proxies, etc.).
    """

    model: str = Field(
        default="gpt-4",
        description="Model name to request (e.g. 'gpt-4o', 'llama3', 'claude-3-haiku')",
    )
    temperature: float | None = Field(
        default=None,
        ge=0.0,
        le=2.0,
        description="Sampling temperature (omitted from request if None)",
    )
    max_tokens: int | None = Field(
        default=None,
        gt=0,
        description="Maximum tokens in the response (omitted from request if None)",
    )


class A2AConfig(BaseModel):
    """Configuration specific to the A2A protocol."""

    agent_card_url: str | None = Field(
        default=None,
        description="URL to fetch the Agent Card from. "
        "Defaults to {url}/.well-known/agent-card.json",
    )
    protocol_binding: Literal["JSONRPC", "HTTP+JSON"] = Field(
        default="HTTP+JSON",
        description="A2A protocol binding to use",
    )
    a2a_version: str = Field(
        default="1.0",
        description="A2A protocol version to request",
    )
    blocking: bool = Field(
        default=True,
        description="Use blocking mode for SendMessage (wait for task completion)",
    )
    use_extended_card: bool = Field(
        default=False,
        description="Fetch the extended Agent Card after authentication",
    )
    enable_streaming: bool = Field(
        default=False,
        description="Use streaming (SSE) for message exchange",
    )


class TargetConfig(BaseModel):
    """Top-level configuration for a remote agent scan target.

    Loaded from a YAML file or constructed programmatically.
    Defines everything needed to connect to and scan a remote agent.

    Example YAML:
        ```yaml
        url: https://agent.example.com
        protocol: a2a
        auth:
          type: bearer
          env_var: AGENT_TOKEN
        tls:
          verify: true
        timeout: 30
        ```
    """

    url: str = Field(description="Base URL of the remote agent")
    protocol: ProtocolType = Field(
        default=ProtocolType.AUTO,
        description="Protocol preset to use",
    )

    # Protocol-specific config
    rest: RestConfig | None = Field(default=None, description="REST-specific configuration")
    openai: OpenAIConfig | None = Field(
        default=None, description="OpenAI-compatible protocol configuration"
    )
    a2a: A2AConfig | None = Field(default=None, description="A2A-specific configuration")

    # Security
    auth: AuthConfig | None = Field(default=None, description="Authentication configuration")
    tls: TlsConfig = Field(default_factory=TlsConfig, description="TLS configuration")

    # Resilience
    retry: RetryConfig = Field(default_factory=RetryConfig, description="Retry configuration")
    timeout: float = Field(default=30.0, gt=0, description="Request timeout in seconds")

    # HTTP
    headers: dict[str, str] = Field(default_factory=dict, description="Additional HTTP headers")
    proxy: str | None = Field(default=None, description="HTTP/HTTPS proxy URL")

    @model_validator(mode="after")
    def _ensure_protocol_config(self) -> TargetConfig:
        """Create default protocol-specific config if not provided."""
        if self.protocol == ProtocolType.A2A and self.a2a is None:
            self.a2a = A2AConfig()
        if self.protocol == ProtocolType.REST and self.rest is None:
            self.rest = RestConfig()
        if self.protocol == ProtocolType.OPENAI and self.openai is None:
            self.openai = OpenAIConfig()
        return self

    @property
    def normalized_url(self) -> str:
        """URL with trailing slash stripped."""
        return self.url.rstrip("/")


class TargetConfigError(Exception):
    """Raised when target configuration is invalid or cannot be loaded."""


def load_target_config(path: Path) -> TargetConfig:
    """Load a target configuration from a YAML file.

    Args:
        path: Path to the YAML configuration file.

    Returns:
        Parsed and validated target configuration.

    Raises:
        TargetConfigError: If the file cannot be read or parsed.
    """
    if not path.exists():
        msg = f"Target config file not found: {path}"
        raise TargetConfigError(msg)

    try:
        raw = path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        msg = f"Invalid YAML in target config: {exc}"
        raise TargetConfigError(msg) from exc

    if not isinstance(data, dict):
        msg = f"Target config must be a YAML mapping, got {type(data).__name__}"
        raise TargetConfigError(msg)

    try:
        return TargetConfig(**data)
    except (ValueError, TypeError, KeyError) as exc:
        msg = f"Invalid target configuration: {exc}"
        raise TargetConfigError(msg) from exc
