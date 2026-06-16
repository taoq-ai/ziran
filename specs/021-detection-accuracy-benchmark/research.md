# Phase 0 Research: Detector Accuracy Benchmark and Threshold Tuning

All Technical Context unknowns are resolved — the four spec clarifications plus a codebase survey left no open `NEEDS CLARIFICATION`. This file records the decisions and the evidence behind them.

## R1 — How to make the harness run detectors offline

- **Decision**: Store the actual recorded **response text + tool_calls** in each labelled example and run the real `DetectorPipeline.evaluate()` against them. Replay the `llm_judge` verdict via a `ReplayLLMClient` implementing `BaseLLMClient`.
- **Rationale**: The existing `benchmarks/accuracy_metrics.py` explicitly skips running detectors because the current ground-truth scenarios only reference *agents*, not recorded responses ("Since we don't run the actual detector pipeline here … that requires live agents, we measure coverage and dataset balance"). Recording the response makes the pipeline runnable deterministically with no network (SC-006), satisfying the "runs against recorded fixtures in CI" assumption.
- **Alternatives considered**:
  - *Live agent execution per benchmark run* — rejected: non-deterministic, slow, needs API keys/cost in CI, defeats SC-006.
  - *Mock each detector's output* — rejected: would test the harness, not the detectors; provides no real accuracy signal.

## R2 — `llm_judge` non-determinism (Clarification Q2)

- **Decision**: Record judge outputs once into the dataset; replay cached verdicts at benchmark time. Re-recording is a deliberate, reviewed action.
- **Rationale**: Deterministic, no live calls, no flaky CI. Matches the recorded-fixtures approach in R1. `BaseLLMClient` is a clean port to stub.
- **Alternatives considered**: live judge at temperature 0 (still drifts, needs keys); N-run majority aggregation (slow, expensive); excluding judge from CI (loses coverage of a core detector). All rejected per the clarification.

## R3 — Per-detector ground truth (Clarification Q1)

- **Decision**: Each example carries `expected_detectors` (per-detector `should_fire`) **plus** an overall `label`. Detectors absent from an example's list are not-applicable and excluded from that detector's metrics.
- **Rationale**: Single-purpose detectors (side_effect, indicator) would show artificially poor numbers if scored against the overall label on examples they were never meant to fire on. The ground-truth schema **already** models this exactly via `ExpectedDetector(detector, should_fire, min_score, reason)` — we reuse it rather than inventing a new shape.
- **Alternatives considered**: overall-label-only scoring (unfair to single-purpose detectors); partial per-detector labels (inconsistent, harder to audit). Rejected.

## R4 — Threshold configuration mechanism

- **Decision**: Introduce a Pydantic `DetectorThresholds` model with today's values as defaults; load `.ziran/detectors.yaml` via the existing `load_yaml_with_env` (`ziran/infrastructure/config/env_yaml.py`) in a new `infrastructure/config/detectors.py`; thread the model into `DetectorPipeline` through `DetectorConfig`. Absent file → defaults (FR-006/FR-007). Invalid/out-of-range → clear error (FR-008).
- **Rationale**: Reuses an existing, tested loader (incl. `!env` for parity with other config). Pydantic gives range validation (`ge=0, le=1`) and a cross-field validator (`hit > safe`) for free, satisfying Type Safety. Defaulting preserves byte-for-byte current behaviour.
- **Alternatives considered**:
  - *Environment variables only* — rejected: poor ergonomics for several related values; no structured validation.
  - *Plain `yaml.safe_load`* — rejected: would lose `!env` parity and duplicate logic already in `env_yaml.py`.
  - *New config dependency (dynaconf/pydantic-settings)* — rejected: violates "every dependency MUST be justified"; existing tools suffice.

## R5 — Regression gate (Clarification Q3)

- **Decision**: Gate on overall pipeline F1; fail if `baseline_f1 - current_f1 > 0.02`. Per-detector metrics reported, non-blocking. Provide `--update-baseline`. CI step path-filtered to `ziran/application/detectors/**`.
- **Rationale**: One defensible headline number; a small absolute band absorbs benign noise while catching real degradation. Mirrors the existing `regression_check.py` + `baseline.json` pattern (incl. `--update-baseline`), so maintainers already know the workflow.
- **Alternatives considered**: per-detector blocking (noisy, single-detector wobble blocks merges); zero tolerance (flaky); recall-guarded gate (deferred — reasonable but adds a second knob; revisit in tuning per FR-011).

## R6 — Metric computation and confidence intervals

- **Decision**: Compute precision, recall, F1, and a 2×2 confusion matrix (TP/FP/FN/TN) per detector and for the pipeline. Reuse the existing `_wilson_ci` helper from `accuracy_metrics.py` to report 95% CIs alongside point estimates.
- **Rationale**: Standard, technology-agnostic metrics required by FR-002/SC-001. Confusion matrix exposes class-imbalance effects (spec edge case) that raw accuracy hides. Reusing the Wilson helper keeps results consistent with the existing accuracy report.
- **Alternatives considered**: scikit-learn metrics — rejected: heavy new dependency for arithmetic we can do directly; violates Simplicity.

## R7 — Dataset location & format

- **Decision**: New YAML examples under `benchmarks/ground_truth/detection/<category>/*.yaml`, validated by a new `DetectionExample` Pydantic model added to `benchmarks/ground_truth/schema.py` (reusing `ExpectedDetector` and the provenance conventions from spec 007). Four category dirs: `clear_refusal`, `partial_compliance`, `full_compliance`, `borderline` (≥50 each).
- **Rationale**: Co-locates with the existing ground-truth dataset and schema (FR-004 "extend, don't fork"), uses the same loader/validation conventions, and keeps category coverage auditable by directory.
- **Alternatives considered**: retrofitting recorded responses onto existing scenarios — rejected: those scenarios are organised by detector-type, not response-category, and lack response text; in-scope retrofit would bloat this feature. A single flat JSON file — rejected: harder to review/curate per category.

## Resolved unknowns summary

| Unknown | Resolution |
|---------|-----------|
| Run detectors offline? | Recorded responses + `ReplayLLMClient` (R1) |
| Judge determinism | Recorded/replayed verdicts (R2) |
| Per-detector truth | `expected_detectors` + overall label, N-A excluded (R3) |
| Threshold config | `DetectorThresholds` Pydantic + `.ziran/detectors.yaml` via `env_yaml` (R4) |
| Gate metric/tolerance | Pipeline F1, 0.02 absolute (R5) |
| Metrics + CIs | P/R/F1 + confusion matrix + Wilson CI, no new deps (R6) |
| Dataset format/location | `benchmarks/ground_truth/detection/<category>/` + `DetectionExample` (R7) |
