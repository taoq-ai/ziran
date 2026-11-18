"""MCP server-initiated requests and the client's replies (spec 071).

A server-surface vector names a request a hostile MCP server sends to the
client (``sampling/createMessage``, ``elicitation/create`` or ``roots/list``).
The hostile server records each reply; the scorer reads the record.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

McpServerMethod = Literal["sampling", "elicitation", "roots"]


class McpServerRequest(BaseModel):
    """The request a server-surface vector sends; the prompt template is its text."""

    method: McpServerMethod
    system_prompt: str | None = Field(default=None, description="Sampling: the system prompt.")
    include_context: Literal["none", "thisServer", "allServers"] | None = Field(
        default=None, description="Sampling: the context the server asks the host to add."
    )
    max_tokens: int = Field(default=200, ge=1, le=4096, description="Sampling: reply budget.")
    fields: dict[str, str] = Field(
        default_factory=dict, description="Elicitation: flat string field name -> description."
    )
    sensitive_fields: list[str] = Field(
        default_factory=list,
        description="Elicitation: fields whose non-blank value in an accept is a finding.",
    )
    denied_roots: list[str] = Field(
        default_factory=list,
        description="Roots: paths (~ is the home folder) a returned root must not contain.",
    )

    @model_validator(mode="after")
    def _check_method_fields(self) -> McpServerRequest:
        if self.method == "elicitation":
            if not self.sensitive_fields:
                raise ValueError("an elicitation request needs sensitive_fields")
            unknown = set(self.sensitive_fields) - set(self.fields)
            if unknown:
                raise ValueError(f"sensitive_fields not in fields: {sorted(unknown)}")
        if self.method == "roots" and not self.denied_roots:
            raise ValueError("a roots request needs denied_roots")
        return self


class McpServerReply(BaseModel):
    """What the client answered to one vector's request.

    ``result`` holds ``text`` (sampling), ``action`` and ``content`` (elicitation, each
    field reduced to ``present`` and ``length``, never the value) or ``roots`` (URIs).
    """

    vector_id: str
    method: McpServerMethod
    status: Literal["reply", "error", "timeout"]
    result: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class McpHostileRecord(BaseModel):
    """The hostile server's record: the client and every reply per vector, in call order."""

    client_name: str = "unknown"
    client_capabilities: dict[str, Any] = Field(default_factory=dict)
    tool_calls: int = Field(default=0, ge=0)
    replies: dict[str, list[McpServerReply]] = Field(default_factory=dict)
