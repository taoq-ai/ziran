"""Claude Code plugin / subagent models and built-in tool vocabulary.

Produced by :func:`ziran.infrastructure.config.claude_code_plugin.load_claude_code`.

Never ``model_dump()`` a whole :class:`ClaudeCodeScan` or :class:`ClaudeCodeAgent` into a report:
``system_prompt`` and MCP ``url``/``args``/``command`` (expanded from the environment) may hold
secrets. Emit explicit fields only.
"""

from __future__ import annotations

import re
from typing import Final

from pydantic import BaseModel, Field, field_validator

from ziran.domain.entities.capability import AgentCapability, CapabilityType
from ziran.domain.entities.registry import ServerEntry
from ziran.domain.tool_classifier import is_dangerous

#: name -> (capability type, dangerous, requires_permission). Insertion order is the
#: "unrestricted" tool set (effective_tools of an agent without a ``tools`` key).
CLAUDE_CODE_BUILTIN_TOOLS: Final[dict[str, tuple[CapabilityType, bool, bool]]] = {
    "Agent": (CapabilityType.TOOL, True, False),
    "Bash": (CapabilityType.TOOL, True, True),
    "Edit": (CapabilityType.DATA_ACCESS, True, True),
    "Glob": (CapabilityType.DATA_ACCESS, False, False),
    "Grep": (CapabilityType.DATA_ACCESS, False, False),
    "NotebookEdit": (CapabilityType.DATA_ACCESS, True, True),
    "Read": (CapabilityType.DATA_ACCESS, False, False),
    "Skill": (CapabilityType.SKILL, False, True),
    "TodoWrite": (CapabilityType.TOOL, False, False),
    "WebFetch": (CapabilityType.EXTERNAL_API, True, True),
    "WebSearch": (CapabilityType.EXTERNAL_API, False, True),
    "Write": (CapabilityType.DATA_ACCESS, True, True),
}

_TOOLS_SPLIT = re.compile(r",\s*(?![^()]*\))")  # commas inside "(...)" belong to the rule


def claude_code_tool_capability(tool: str) -> AgentCapability:
    """AgentCapability for one declared Claude Code tool string (verbatim as id and name)."""
    row = CLAUDE_CODE_BUILTIN_TOOLS.get(tool.split("(", 1)[0])
    if row is None:
        mcp = tool.startswith("mcp__")
        row = (CapabilityType.EXTERNAL_API if mcp else CapabilityType.TOOL, is_dangerous(tool), mcp)
    kind, dangerous, permission = row
    return AgentCapability(
        id=tool, name=tool, type=kind, dangerous=dangerous, requires_permission=permission
    )


class ClaudeCodeParseIssue(BaseModel):
    """A problem in a Claude Code file. ``message`` never contains file content."""

    file: str
    line: int | None = None
    message: str


class ClaudeCodeAgent(BaseModel):
    """One subagent definition (``agents/*.md`` frontmatter + body)."""

    name: str = Field(min_length=1)
    description: str = ""
    tools: list[str] | None = None
    model: str | None = None
    file: str
    key_lines: dict[str, int] = Field(default_factory=dict)
    system_prompt: str = ""
    body_line: int = Field(ge=1)

    @field_validator("tools", mode="before")
    @classmethod
    def _normalise_tools(cls, value: object) -> object:
        if isinstance(value, str):
            value = _TOOLS_SPLIT.split(value)
        elif not isinstance(value, list):
            return value  # None stays None; other types fail pydantic's list check
        if not all(isinstance(t, str) for t in value):
            raise ValueError("tools entries must be strings")
        tools = list(dict.fromkeys(t.strip() for t in value if t.strip()))
        return tools or None

    @property
    def unrestricted(self) -> bool:
        return self.tools is None

    @property
    def effective_tools(self) -> list[str]:
        return list(CLAUDE_CODE_BUILTIN_TOOLS if self.tools is None else self.tools)

    @property
    def capabilities(self) -> list[AgentCapability]:
        return [claude_code_tool_capability(t) for t in self.effective_tools]

    def line_of(self, key: str) -> int:
        return self.key_lines.get(key, 1)


class ClaudeCodeHook(BaseModel):
    event: str
    matcher: str | None = None
    type: str
    command: str | None = None
    file: str


class ClaudeCodePlugin(BaseModel):
    name: str = Field(min_length=1)
    version: str | None = None
    description: str | None = None
    file: str


class ClaudeCodeScan(BaseModel):
    root: str
    plugin: ClaudeCodePlugin | None = None
    agents: list[ClaudeCodeAgent] = Field(default_factory=list)
    hooks: list[ClaudeCodeHook] = Field(default_factory=list)
    mcp_servers: list[ServerEntry] = Field(default_factory=list)
    issues: list[ClaudeCodeParseIssue] = Field(default_factory=list)
    files_analyzed: int = 0

    @property
    def detected(self) -> bool:
        return self.plugin is not None or bool(self.agents) or bool(self.issues)
