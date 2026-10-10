"""CrewAI project models read statically from agents.yaml, tasks.yaml and crew.py.

Produced by :func:`ziran.infrastructure.config.crewai_project.load_crewai`. One
:class:`CrewAIAgent` is one agents.yaml entry.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class CrewAIIssue(BaseModel):
    """A problem in a CrewAI project file. ``message`` never contains file content."""

    file: str
    line: int | None = None
    message: str


class CrewAITask(BaseModel):
    """A task assigned to an agent, with the tools the task itself names."""

    name: str
    tools: list[str] = Field(default_factory=list)


class CrewAIAgent(BaseModel):
    """One agents.yaml entry with its own tools and the tasks assigned to it."""

    name: str
    file: str
    line: int = 1
    agent_tools: list[str] = Field(default_factory=list)
    tasks: list[CrewAITask] = Field(default_factory=list)
    errors: list[CrewAIIssue] = Field(default_factory=list)

    @property
    def tools(self) -> list[str]:
        """Agent tools, then each task's tools in task order, without duplicates."""
        return list(dict.fromkeys([*self.agent_tools, *(t for k in self.tasks for t in k.tools)]))


class CrewAIScan(BaseModel):
    root: str
    agents: list[CrewAIAgent] = Field(default_factory=list)
    issues: list[CrewAIIssue] = Field(default_factory=list)
    files_analyzed: int = 0

    @property
    def detected(self) -> bool:
        return bool(self.agents) or bool(self.issues)
