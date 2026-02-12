"""A2A (Agent-to-Agent) protocol data models.

Pydantic models representing the A2A protocol data structures needed
for Ziran's scanning capabilities. Based on the A2A Protocol
Specification RC v1.0.

These models are intentionally lightweight — they capture only the
fields Ziran needs as a *client* (scanner), not a server implementation.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# ── Agent Discovery Objects ──────────────────────────────────────


class A2AAgentProvider(BaseModel):
    """Service provider information from an Agent Card."""

    organization: str = ""
    url: str = ""


class A2AAgentCapabilities(BaseModel):
    """Declared capabilities of an A2A agent."""

    streaming: bool = False
    push_notifications: bool = Field(default=False, alias="pushNotifications")
    extended_agent_card: bool = Field(default=False, alias="extendedAgentCard")

    model_config = {"populate_by_name": True}


class A2AAgentSkill(BaseModel):
    """A skill declared in an Agent Card."""

    id: str
    name: str
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    examples: list[str] = Field(default_factory=list)
    input_modes: list[str] = Field(default_factory=list, alias="inputModes")
    output_modes: list[str] = Field(default_factory=list, alias="outputModes")

    model_config = {"populate_by_name": True}


class A2ASecurityScheme(BaseModel):
    """A security scheme declared in an Agent Card.

    Simplified representation — captures the scheme type and key fields
    without modelling every OAuth flow variant.
    """

    type: str = Field(
        default="unknown",
        description="Inferred type: apiKey, http, oauth2, openIdConnect, mutualTls",
    )
    description: str = ""
    raw: dict[str, Any] = Field(
        default_factory=dict,
        description="Full raw security scheme object for detailed analysis",
    )


class A2AAgentInterface(BaseModel):
    """Declares a protocol binding + URL combination."""

    url: str
    protocol_binding: str = Field(default="HTTP+JSON", alias="protocolBinding")
    protocol_version: str = Field(default="1.0", alias="protocolVersion")
    tenant: str | None = None

    model_config = {"populate_by_name": True}


class A2AAgentCard(BaseModel):
    """An A2A Agent Card — the self-describing manifest of an agent.

    Parsed from ``/.well-known/agent-card.json`` or a custom URL.
    """

    name: str
    description: str = ""
    version: str = ""
    provider: A2AAgentProvider | None = None
    documentation_url: str | None = Field(default=None, alias="documentationUrl")
    icon_url: str | None = Field(default=None, alias="iconUrl")

    supported_interfaces: list[A2AAgentInterface] = Field(
        default_factory=list, alias="supportedInterfaces"
    )
    capabilities: A2AAgentCapabilities = Field(default_factory=A2AAgentCapabilities)
    skills: list[A2AAgentSkill] = Field(default_factory=list)

    default_input_modes: list[str] = Field(default_factory=list, alias="defaultInputModes")
    default_output_modes: list[str] = Field(default_factory=list, alias="defaultOutputModes")

    security_schemes: dict[str, dict[str, Any]] = Field(
        default_factory=dict, alias="securitySchemes"
    )
    security: list[dict[str, list[str]]] = Field(default_factory=list)

    model_config = {"populate_by_name": True}

    def parse_security_schemes(self) -> dict[str, A2ASecurityScheme]:
        """Parse raw securitySchemes into typed objects.

        Returns:
            Mapping of scheme name to parsed security scheme.
        """
        result: dict[str, A2ASecurityScheme] = {}
        for name, raw in self.security_schemes.items():
            scheme_type = "unknown"
            if "apiKeySecurityScheme" in raw:
                scheme_type = "apiKey"
            elif "httpAuthSecurityScheme" in raw:
                scheme_type = "http"
            elif "oauth2SecurityScheme" in raw:
                scheme_type = "oauth2"
            elif "openIdConnectSecurityScheme" in raw:
                scheme_type = "openIdConnect"
            elif "mtlsSecurityScheme" in raw:
                scheme_type = "mutualTls"

            description = ""
            for v in raw.values():
                if isinstance(v, dict) and "description" in v:
                    description = v["description"]
                    break

            result[name] = A2ASecurityScheme(type=scheme_type, description=description, raw=raw)
        return result


# ── Protocol Messages ────────────────────────────────────────────


class A2APart(BaseModel):
    """Content part within a message or artifact."""

    text: str | None = None
    raw: str | None = None
    url: str | None = None
    data: dict[str, Any] | None = None
    filename: str | None = None
    media_type: str | None = Field(default=None, alias="mediaType")

    model_config = {"populate_by_name": True}


class A2AMessage(BaseModel):
    """A message in the A2A protocol."""

    message_id: str | None = Field(default=None, alias="messageId")
    task_id: str | None = Field(default=None, alias="taskId")
    context_id: str | None = Field(default=None, alias="contextId")
    role: str = "ROLE_USER"
    parts: list[A2APart] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"populate_by_name": True}


class A2AArtifact(BaseModel):
    """An output artifact from a task."""

    artifact_id: str = Field(default="", alias="artifactId")
    name: str = ""
    description: str = ""
    parts: list[A2APart] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"populate_by_name": True}


class A2ATaskStatus(BaseModel):
    """Status container for a task."""

    state: str = "TASK_STATE_UNSPECIFIED"
    message: A2AMessage | None = None
    timestamp: str | None = None


class A2ATask(BaseModel):
    """The core unit of work in A2A."""

    id: str
    context_id: str = Field(default="", alias="contextId")
    status: A2ATaskStatus = Field(default_factory=A2ATaskStatus)
    artifacts: list[A2AArtifact] = Field(default_factory=list)
    history: list[A2AMessage] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"populate_by_name": True}

    @property
    def is_terminal(self) -> bool:
        """Check if the task is in a terminal state."""
        return self.status.state in {
            "TASK_STATE_COMPLETED",
            "TASK_STATE_FAILED",
            "TASK_STATE_CANCELED",
            "TASK_STATE_REJECTED",
            "TASK_STATE_AUTH_REQUIRED",
        }

    @property
    def is_input_required(self) -> bool:
        """Check if the agent is asking for more input."""
        return self.status.state == "TASK_STATE_INPUT_REQUIRED"

    @property
    def is_auth_required(self) -> bool:
        """Check if secondary authentication is needed."""
        return self.status.state == "TASK_STATE_AUTH_REQUIRED"

    def extract_text(self) -> str:
        """Extract text content from all artifacts.

        Returns:
            Combined text from all artifact parts.
        """
        texts: list[str] = []
        for artifact in self.artifacts:
            for part in artifact.parts:
                if part.text:
                    texts.append(part.text)
        return "\n".join(texts)


# ── Request / Response Wrappers ──────────────────────────────────


class A2ASendMessageConfiguration(BaseModel):
    """Configuration for a SendMessage request."""

    accepted_output_modes: list[str] = Field(
        default_factory=lambda: ["text/plain"], alias="acceptedOutputModes"
    )
    blocking: bool = False
    history_length: int | None = Field(default=None, alias="historyLength")

    model_config = {"populate_by_name": True}


class A2ASendMessageRequest(BaseModel):
    """A complete SendMessage request body."""

    message: A2AMessage
    configuration: A2ASendMessageConfiguration | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class A2ASendMessageResponse(BaseModel):
    """Response from SendMessage — wraps either a Task or a Message.

    The A2A spec says the response contains exactly one of ``task``
    or ``message``.
    """

    task: A2ATask | None = None
    message: A2AMessage | None = None

    def extract_text(self) -> str:
        """Extract text content from the response.

        Returns:
            The text content from the task artifacts or message parts.
        """
        if self.task:
            return self.task.extract_text()
        if self.message:
            return "\n".join(p.text for p in self.message.parts if p.text)
        return ""
