"""Streaming response models for real-time agent communication.

Defines chunk-based response models used when agents support
streaming (SSE, WebSocket, or native framework streaming).
The scanner accumulates chunks into a full ``AgentResponse``
for detection pipeline compatibility.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AgentResponseChunk(BaseModel):
    """A single chunk from a streaming agent response.

    Emitted incrementally during streaming agent invocations.
    The scanner accumulates these into a full ``AgentResponse``
    once ``is_final`` is True.
    """

    content_delta: str = Field(
        default="",
        description="Incremental text content (may be empty for tool-call-only chunks)",
    )
    tool_call_delta: dict[str, Any] | None = Field(
        default=None,
        description="Incremental tool call data (partial function name, arguments)",
    )
    is_final: bool = Field(
        default=False,
        description="True when this is the last chunk in the stream",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Protocol-specific metadata for this chunk",
    )


class LLMResponseChunk(BaseModel):
    """A single chunk from a streaming LLM completion.

    Used by the internal LLM backbone when streaming is enabled
    (e.g., for adaptive strategy reasoning or future agent features).
    """

    content_delta: str = Field(
        default="",
        description="Incremental text content",
    )
    is_final: bool = Field(
        default=False,
        description="True when this is the last chunk",
    )
    model: str = Field(
        default="",
        description="Model that generated this chunk",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Provider-specific metadata",
    )
