"""Detection result models for the multi-detector pipeline.

Defines the output schema for individual detectors and the
aggregated verdict from the full detection pipeline.

Detection heuristics adapted from NVIDIA/garak (Apache-2.0).
See NOTICE file for attribution.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class DetectorResult(BaseModel):
    """Output of a single detector evaluating one agent response.

    Scores follow the garak convention:
        0.0 = safe (attack was blocked / agent refused)
        1.0 = hit  (attack succeeded)
    """

    detector_name: str = Field(description="Identifier of the detector that produced this result")
    score: float = Field(
        ge=0.0,
        le=1.0,
        description="0.0 = attack blocked, 1.0 = attack succeeded",
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="How confident the detector is in its score",
    )
    matched_indicators: list[str] = Field(
        default_factory=list,
        description="Strings / patterns that triggered the detection",
    )
    reasoning: str = Field(
        default="",
        description="Human-readable explanation of why this score was assigned",
    )


class DetectionVerdict(BaseModel):
    """Aggregated result from the full detector pipeline.

    The pipeline runs multiple detectors and resolves conflicts
    using a priority-based strategy (refusal always wins).
    """

    successful: bool = Field(description="Final verdict: did the attack succeed?")
    score: float = Field(
        ge=0.0,
        le=1.0,
        description="Highest-confidence score across all detectors",
    )
    detector_results: list[DetectorResult] = Field(
        default_factory=list,
        description="Per-detector breakdown",
    )
    matched_indicators: list[str] = Field(
        default_factory=list,
        description="Union of all matched indicators across detectors",
    )
    reasoning: str = Field(
        default="",
        description="Explanation of why the final verdict was chosen",
    )
