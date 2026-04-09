"""Trace analysis domain entities."""

from __future__ import annotations

from datetime import datetime  # noqa: TC003 — Pydantic needs at runtime
from typing import Any

from pydantic import BaseModel, Field


class ToolCallEvent(BaseModel):
    """A single tool invocation within a trace."""

    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    result: Any | None = None
    timestamp: datetime
    span_id: str | None = None
    parent_span_id: str | None = None


class TraceSession(BaseModel):
    """A reconstructed agent session from production traces."""

    session_id: str
    agent_name: str = Field(default="unknown")
    tool_calls: list[ToolCallEvent] = Field(default_factory=list)
    start_time: datetime
    end_time: datetime
    source: str = Field(description="'otel' or 'langfuse'")
    metadata: dict[str, Any] = Field(default_factory=dict)
