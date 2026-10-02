"""Cheap-model prefilter before the LLM judge (spec 043).

Tier order in :class:`~ziran.application.detectors.pipeline.DetectorPipeline`:
deterministic detectors (plus the semantic tier, spec 042) -> cheap prefilter
-> full LLM judge (single or ensemble, spec 041).

Routing, when the prefilter is enabled:
  * the deterministic results already decide the verdict -> no model call;
  * otherwise the cheap model judges; its verdict decides when it is
    success/failure, its confidence is at least the escalation threshold and
    it does not contradict the deterministic lean;
  * everything else escalates to the full judge.

This module holds the config block and the pure routing helpers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ziran.domain.entities.detection import DetectorResult

TIERS: tuple[str, ...] = ("deterministic", "cheap", "escalated")
Lean = Literal["success", "failure"]
EscalationReason = Literal["ambiguous", "low_confidence", "conflict", "error"]

_SUCCESS_SIGNAL_DETECTORS = ("indicator", "side_effect", "authorization")
_FAILURE_SIGNAL_DETECTORS = ("refusal", "indicator", "side_effect", "authorization")


class PrefilterConfig(BaseModel):
    """Cheap-model prefilter before the LLM judge (spec 043). Disabled by default."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = False
    provider: str | None = Field(
        default=None, description="Provider for the cheap model; None = scan's --llm-provider."
    )
    model: str | None = Field(
        default=None, min_length=1, description="Cheap model (the issue's prefilter_model)."
    )
    escalate_below: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Cheap verdicts below this confidence escalate to the full judge.",
    )

    @model_validator(mode="after")
    def _check(self) -> PrefilterConfig:
        if self.provider is not None and self.model is None:
            raise ValueError("'provider' requires 'model'")
        if self.enabled and self.model is None:
            raise ValueError("'model' is required when the prefilter is enabled")
        return self


def deterministic_lean(
    results: Sequence[DetectorResult], *, hit: float, safe: float
) -> Lean | None:
    """Direction of the non-deciding built-in detector signals.

    A failure signal is a refusal/indicator/side_effect/authorization result with
    ``score <= safe``; a success signal is an indicator/side_effect/authorization
    result with ``score >= hit`` (refusal's 1.0 means "no refusal phrase", not
    compliance). Returns the lean only when all signals agree; other results
    (custom, semantic, llm_judge) are ignored.
    """
    failure = any(r.detector_name in _FAILURE_SIGNAL_DETECTORS and r.score <= safe for r in results)
    success = any(r.detector_name in _SUCCESS_SIGNAL_DETECTORS and r.score >= hit for r in results)
    if failure == success:
        return None
    return "failure" if failure else "success"


def escalation_reason(
    cheap: DetectorResult | None,
    lean: Lean | None,
    *,
    min_confidence: float,
    hit: float,
    safe: float,
) -> EscalationReason | None:
    """Why the cheap verdict must escalate, or None when it decides."""
    if cheap is None:
        return "error"
    if safe < cheap.score < hit:
        return "ambiguous"
    if cheap.confidence < min_confidence:
        return "low_confidence"
    if (cheap.score >= hit and lean == "failure") or (cheap.score <= safe and lean == "success"):
        return "conflict"
    return None
