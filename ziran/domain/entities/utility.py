"""Utility measurement models for security-utility tradeoff analysis.

Defines task specifications and results for measuring agent utility
before and after attack campaigns (AgentDojo-style).
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class UtilityTask(BaseModel):
    """A legitimate task used to measure agent utility.

    Each task defines a prompt to send and patterns that indicate
    whether the agent completed the task successfully.
    """

    id: str = Field(description="Unique task identifier")
    description: str = Field(description="Human-readable task description")
    prompt: str = Field(description="The task prompt to send to the agent")
    success_indicators: list[str] = Field(
        min_length=1,
        description="Substrings that indicate the task was completed successfully",
    )
    failure_indicators: list[str] = Field(
        default_factory=list,
        description="Substrings that indicate the agent refused or failed the task",
    )


class UtilityTaskResult(BaseModel):
    """Result of running a single utility task."""

    task_id: str
    successful: bool
    response_snippet: str = Field(description="First 500 characters of agent response")
    matched_indicators: list[str] = Field(default_factory=list)
    duration_seconds: float = Field(ge=0.0)


class UtilityMetrics(BaseModel):
    """Aggregate utility measurement from pre- and post-attack task runs.

    The utility delta indicates how much the agent's ability to perform
    legitimate tasks degraded due to the attack campaign.

    A positive delta means the agent became *less* capable after attacks.
    """

    baseline_score: float = Field(ge=0.0, le=1.0, description="Pre-attack task success rate")
    post_attack_score: float = Field(ge=0.0, le=1.0, description="Post-attack task success rate")
    utility_delta: float = Field(
        ge=-1.0, le=1.0, description="baseline - post_attack (positive = degradation)"
    )
    tasks_run: int = Field(ge=0)
    baseline_results: list[UtilityTaskResult] = Field(default_factory=list)
    post_attack_results: list[UtilityTaskResult] = Field(default_factory=list)
