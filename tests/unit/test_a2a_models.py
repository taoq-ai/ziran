"""Unit tests for A2A protocol data models."""

from __future__ import annotations

from ziran.domain.entities.a2a import (
    A2AAgentCapabilities,
    A2AAgentCard,
    A2AAgentProvider,
    A2AAgentSkill,
    A2AArtifact,
    A2AMessage,
    A2APart,
    A2ASendMessageConfiguration,
    A2ASendMessageRequest,
    A2ASendMessageResponse,
    A2ATask,
    A2ATaskStatus,
)

# ──────────────────────────────────────────────────────────────────────
# A2AAgentCard
# ──────────────────────────────────────────────────────────────────────


class TestA2AAgentCard:
    """Tests for A2A Agent Card model."""

    def test_minimal_card(self) -> None:
        card = A2AAgentCard(name="TestAgent", version="1.0")
        assert card.name == "TestAgent"
        assert card.version == "1.0"
        assert card.skills == []
        assert card.description == ""

    def test_full_card(self) -> None:
        card = A2AAgentCard(
            name="FullAgent",
            description="A full agent",
            version="2.0",
            provider=A2AAgentProvider(
                organization="TestOrg",
                url="https://test.org",
            ),
            skills=[
                A2AAgentSkill(
                    id="search",
                    name="Web Search",
                    description="Searches the web",
                    tags=["search", "web"],
                    examples=["search for cats"],
                )
            ],
            capabilities=A2AAgentCapabilities(
                streaming=True,
                push_notifications=True,
                extended_agent_card=True,
            ),
            default_input_modes=["text/plain"],
            default_output_modes=["text/plain", "text/html"],
        )
        assert len(card.skills) == 1
        assert card.skills[0].id == "search"
        assert card.capabilities is not None
        assert card.capabilities.streaming is True

    def test_parse_security_schemes_http(self) -> None:
        card = A2AAgentCard(
            name="SecureAgent",
            version="1.0",
            security_schemes={
                "bearer_auth": {
                    "httpAuthSecurityScheme": {
                        "scheme": "bearer",
                        "description": "JWT Bearer",
                    }
                }
            },
            security=[{"bearer_auth": []}],
        )
        schemes = card.parse_security_schemes()
        assert len(schemes) == 1
        assert "bearer_auth" in schemes
        assert schemes["bearer_auth"].type == "http"
        assert schemes["bearer_auth"].description == "JWT Bearer"

    def test_parse_security_schemes_api_key(self) -> None:
        card = A2AAgentCard(
            name="ApiAgent",
            version="1.0",
            security_schemes={
                "api_key": {
                    "apiKeySecurityScheme": {
                        "in": "header",
                        "name": "X-API-Key",
                    }
                }
            },
        )
        schemes = card.parse_security_schemes()
        assert len(schemes) == 1
        assert schemes["api_key"].type == "apiKey"

    def test_camel_case_alias(self) -> None:
        """Ensure camelCase JSON fields are parsed correctly."""
        card = A2AAgentCard.model_validate(
            {
                "name": "AliasAgent",
                "version": "1.0",
                "defaultInputModes": ["text/plain"],
                "defaultOutputModes": ["text/html"],
                "supportedInterfaces": [
                    {"url": "https://example.com", "protocolBinding": "HTTP+JSON"}
                ],
            }
        )
        assert card.default_input_modes == ["text/plain"]
        assert len(card.supported_interfaces) == 1
        assert card.supported_interfaces[0].protocol_binding == "HTTP+JSON"


# ──────────────────────────────────────────────────────────────────────
# A2AAgentSkill
# ──────────────────────────────────────────────────────────────────────


class TestA2AAgentSkill:
    """Tests for A2A Agent Skill model."""

    def test_minimal_skill(self) -> None:
        skill = A2AAgentSkill(id="s1", name="Skill One")
        assert skill.id == "s1"
        assert skill.name == "Skill One"
        assert skill.tags == []

    def test_full_skill(self) -> None:
        skill = A2AAgentSkill(
            id="translate",
            name="Translate",
            description="Translates between languages",
            tags=["language", "translation"],
            examples=["translate hello to French"],
            input_modes=["text/plain"],
            output_modes=["text/plain"],
        )
        assert "language" in skill.tags
        assert len(skill.examples) == 1


# ──────────────────────────────────────────────────────────────────────
# A2ATask
# ──────────────────────────────────────────────────────────────────────


class TestA2ATask:
    """Tests for A2A Task model."""

    def test_submitted_task(self) -> None:
        task = A2ATask(
            id="task-001",
            status=A2ATaskStatus(state="submitted"),
        )
        assert not task.is_terminal
        assert not task.is_input_required
        assert not task.is_auth_required

    def test_completed_task(self) -> None:
        task = A2ATask(
            id="task-002",
            status=A2ATaskStatus(state="TASK_STATE_COMPLETED"),
            artifacts=[
                A2AArtifact(
                    artifact_id="art-1",
                    parts=[A2APart(text="Result text")],
                )
            ],
        )
        assert task.is_terminal
        assert task.extract_text() == "Result text"

    def test_failed_task(self) -> None:
        task = A2ATask(
            id="task-003",
            status=A2ATaskStatus(
                state="TASK_STATE_FAILED",
                message=A2AMessage(
                    role="agent",
                    parts=[A2APart(text="Something went wrong")],
                ),
            ),
        )
        assert task.is_terminal

    def test_input_required_task(self) -> None:
        task = A2ATask(
            id="task-004",
            status=A2ATaskStatus(state="TASK_STATE_INPUT_REQUIRED"),
        )
        assert task.is_input_required

    def test_auth_required_task(self) -> None:
        task = A2ATask(
            id="task-005",
            status=A2ATaskStatus(state="TASK_STATE_AUTH_REQUIRED"),
        )
        assert task.is_auth_required
        assert task.is_terminal

    def test_extract_text_from_history(self) -> None:
        task = A2ATask(
            id="task-006",
            status=A2ATaskStatus(state="TASK_STATE_COMPLETED"),
            artifacts=[
                A2AArtifact(
                    artifact_id="a1",
                    parts=[A2APart(text="Hello from artifact")],
                )
            ],
        )
        assert task.extract_text() == "Hello from artifact"


# ──────────────────────────────────────────────────────────────────────
# A2AMessage & A2APart
# ──────────────────────────────────────────────────────────────────────


class TestA2AMessage:
    """Tests for A2A message and parts."""

    def test_text_part(self) -> None:
        part = A2APart(text="Hello world")
        assert part.text == "Hello world"
        assert part.raw is None

    def test_file_part(self) -> None:
        part = A2APart(
            url="https://example.com/file.pdf",
            filename="file.pdf",
            media_type="application/pdf",
        )
        assert part.url == "https://example.com/file.pdf"

    def test_message_with_parts(self) -> None:
        msg = A2AMessage(
            role="user",
            parts=[
                A2APart(text="Explain this"),
                A2APart(url="https://example.com/doc.pdf"),
            ],
        )
        assert msg.role == "user"
        assert len(msg.parts) == 2


# ──────────────────────────────────────────────────────────────────────
# A2ASendMessageRequest / Response
# ──────────────────────────────────────────────────────────────────────


class TestA2ASendMessage:
    """Tests for A2A send message request/response models."""

    def test_request_build(self) -> None:
        req = A2ASendMessageRequest(
            message=A2AMessage(
                role="user",
                parts=[A2APart(text="Hello")],
            ),
            configuration=A2ASendMessageConfiguration(
                blocking=True,
                accepted_output_modes=["text/plain"],
            ),
        )
        assert req.message.role == "user"
        assert req.configuration is not None
        assert req.configuration.blocking is True

    def test_response_extract_text(self) -> None:
        resp = A2ASendMessageResponse(
            task=A2ATask(
                id="task-resp",
                status=A2ATaskStatus(state="completed"),
                artifacts=[
                    A2AArtifact(
                        artifact_id="a1",
                        parts=[A2APart(text="Answer")],
                    )
                ],
            ),
        )
        assert resp.extract_text() == "Answer"

    def test_response_with_message(self) -> None:
        resp = A2ASendMessageResponse(
            message=A2AMessage(
                role="agent",
                parts=[A2APart(text="Quick reply")],
            ),
        )
        assert resp.extract_text() == "Quick reply"
