# Implementation Plan: Detector Accuracy Benchmark and Threshold Tuning

**Branch**: `021-detection-accuracy-benchmark` | **Date**: 2026-06-12 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/021-detection-accuracy-benchmark/spec.md`

## Summary

Make detector accuracy a measured, published, regression-protected property of ZIRAN. Today the four detectors (refusal, indicator, side-effect, llm_judge) decide compromise via module-level constants (`_HIT_THRESHOLD=0.7`, `_SAFE_THRESHOLD=0.3`, side-effect confidence gate `0.8`) with no measured basis. We add:

1. A labelled `(attack, response)` dataset (≥200 examples, ≥50/category) carrying recorded response text, tool calls, a recorded `llm_judge` verdict, per-detector expected verdicts, and an overall label.
2. An offline harness (`benchmarks/detection_accuracy.py`) that runs the **real** detector pipeline against that dataset and emits precision/recall/F1 + confusion matrix per detector and for the pipeline.
3. Operator-tunable thresholds via `.ziran/detectors.yaml` (defaults preserve current behaviour), loaded through the existing `!env` YAML loader and validated by a Pydantic model.
4. A CI regression gate that fails when pipeline F1 drops > 0.02 below a recorded baseline, scoped to changes touching detector code.
5. Methodology + baseline docs at `docs/reference/benchmarks/detection-accuracy.md`.

**Key reuse finding**: the existing `benchmarks/accuracy_metrics.py` deliberately does **not** run the detectors ("we don't run the actual detector pipeline here … that requires live agents") — it only measures dataset balance. The ground-truth schema already defines `ExpectedDetector(detector, should_fire, min_score)`, the regression `baseline.json` + `regression_check.py` pattern already exists, and `ziran/infrastructure/config/env_yaml.py` already provides `!env` loading. This feature fills the "actually run the detectors, offline" gap and threads thresholds through config.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary Dependencies**: Pydantic v2 (threshold + dataset models), PyYAML (dataset + config loading, reusing `load_yaml_with_env`), Click (benchmark CLI entry point), existing `ziran.application.detectors` pipeline. No new runtime dependencies.
**Storage**: YAML files for the labelled dataset (under `benchmarks/ground_truth/detection/`) and for operator config (`.ziran/detectors.yaml`); JSON result + baseline artifacts under `benchmarks/results/` (existing pattern).
**Testing**: pytest with `@pytest.mark.unit` / `@pytest.mark.integration` markers; offline (no live model calls).
**Target Platform**: Linux/macOS dev + CI runners.
**Project Type**: Single project (library + CLI + benchmark tooling) — hexagonal layout already in place.
**Performance Goals**: Full benchmark run completes in CI in < 60s (offline, no network).
**Constraints**: Deterministic / reproducible (SC-006) — no live model calls; `llm_judge` verdicts are replayed from recorded fixtures. Default detection behaviour MUST be byte-for-byte unchanged when no config is present (FR-007).
**Scale/Scope**: ≥200 labelled examples, ≥50 per category (clear refusal / partial compliance / full compliance / borderline); four detectors in scope.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Assessment |
|-----------|------------|
| **I. Hexagonal Architecture** | ✅ Threshold model (`DetectorThresholds`, Pydantic) lives with pipeline config in `application/detectors`; file-reading loader lives in `infrastructure/config/detectors.py` (reusing `env_yaml`); pipeline stays in `application`; the benchmark harness + replay LLM client are tooling under `benchmarks/` (same layer as existing benchmarks), invoking the application pipeline through its public `evaluate()` API. No inward dependency violations. |
| **II. Type Safety** | ✅ New data structures are Pydantic v2 models (`DetectorThresholds`, `DetectionExample`, `DetectorAccuracyResult`). Full annotations; mypy strict. Threshold validation (range 0–1, hit > safe) enforced by Pydantic validators. |
| **III. Test Coverage** | ✅ Unit tests: threshold model/loader, metric math, replay client. Integration test: harness runs the real pipeline against a fixture dataset slice. Target ≥85%. |
| **IV. Async-First** | ✅ `DetectorPipeline.evaluate()` is async; the harness drives it via `asyncio.run` at the CLI entry point (permitted sync wrapper). No new blocking I/O in async paths. |
| **V. Extensibility via Adapters** | ✅ Thresholds become YAML config, not code (mirrors "new attack vectors as YAML"). `llm_judge` replay implements the existing `BaseLLMClient` port. No detector interface changes required. |
| **VI. Simplicity** | ✅ Reuses Wilson-CI helper, `baseline.json`/`regression_check` pattern, and `load_yaml_with_env`. No new dependencies. Old `accuracy_metrics.py` retained (complementary balance metric), not duplicated. |

**Result**: PASS — no violations. Complexity Tracking left empty.

## Project Structure

### Documentation (this feature)

```text
specs/021-detection-accuracy-benchmark/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output (dataset schema, config schema, CLI contract)
└── tasks.md             # Phase 2 output (/speckit.tasks — NOT created here)
```

### Source Code (repository root)

```text
ziran/
├── application/
│   └── detectors/
│       ├── pipeline.py              # MODIFY: read thresholds from DetectorThresholds
│       │                            #         instead of module constants; preserve defaults
│       └── thresholds.py            # NEW: DetectorThresholds Pydantic model + defaults
├── infrastructure/
│   └── config/
│       ├── env_yaml.py              # REUSE: load_yaml_with_env
│       └── detectors.py             # NEW: load .ziran/detectors.yaml → DetectorThresholds
│                                    #      (validation + clear errors; defaults when absent)
└── domain/                          # unchanged

benchmarks/
├── detection_accuracy.py            # NEW: harness — run real pipeline over labelled dataset,
│                                    #      emit per-detector + pipeline P/R/F1 + confusion matrix
├── detection_regression.py          # NEW (or extend regression_check.py): F1 gate vs baseline
├── replay_llm_client.py             # NEW: BaseLLMClient impl replaying recorded judge verdicts
├── accuracy_metrics.py              # UNCHANGED: dataset-balance metric (complementary)
├── ground_truth/
│   ├── schema.py                    # EXTEND: DetectionExample model (reuses ExpectedDetector)
│   └── detection/                   # NEW: labelled (attack,response) YAML examples, ≥50/category
│       ├── clear_refusal/
│       ├── partial_compliance/
│       ├── full_compliance/
│       └── borderline/
└── results/
    ├── detection_accuracy.json          # NEW: machine-readable run output
    └── detection_accuracy_baseline.json # NEW: recorded baseline for the gate

docs/reference/benchmarks/
├── coverage-comparison.md           # MODIFY: add a detection-accuracy row
└── detection-accuracy.md            # NEW: methodology + baseline + threshold tuning rationale

.github/workflows/                   # MODIFY: add detection-accuracy regression step
                                     #         (path-filtered to detector code)

tests/
├── unit/                            # threshold model, config loader, metric math, replay client
└── integration/                     # harness end-to-end over a fixture dataset slice
```

**Structure Decision**: Single-project hexagonal layout (already in place). The configurable-threshold work lands in `ziran/` across `application` (model + pipeline) and `infrastructure` (file loader); the measurement work lands in `benchmarks/` alongside the existing benchmark suite, consuming the pipeline through its public async API. This keeps the domain untouched and confines new file I/O to infrastructure/tooling.

## Design Notes (carried into Phase 1)

- **Threshold threading**: replace `_HIT_THRESHOLD` / `_SAFE_THRESHOLD` module constants and the inline confidence gates (`0.5`, `0.7`, `0.8`) with fields on `DetectorThresholds`, defaulted to today's values so FR-007 holds. `DetectorPipeline.__init__` gains an optional `thresholds: DetectorThresholds | None`; `DetectorConfig` is the natural carrier. Loader returns defaults when `.ziran/detectors.yaml` is absent (FR-006) and raises a clear `ValueError`/`EnvVarError`-style message on invalid/out-of-range values (FR-008).
- **Per-detector vs pipeline scoring** (Q1): each `DetectionExample` lists `expected_detectors` (reusing `ExpectedDetector.should_fire`); detectors not listed for an example are *not-applicable* and excluded from that detector's confusion matrix. The overall `label` drives the pipeline confusion matrix.
- **Offline `llm_judge`** (Q2): each example stores a recorded judge verdict; `ReplayLLMClient` returns it keyed by `example_id`, so `DetectorPipeline(llm_client=ReplayLLMClient(...))` runs the judge deterministically with zero network. Re-recording is a manual, reviewed step documented in the methodology.
- **Regression gate** (Q3): primary metric = pipeline F1; fail if `baseline_f1 - current_f1 > 0.02`. Per-detector metrics reported but non-blocking. `--update-baseline` flag mirrors `regression_check.py`. CI step path-filtered to `ziran/application/detectors/**`.
- **Dataset reuse** (FR-004): the new `detection/` examples extend the spec-007 ground-truth fixtures and schema (`ExpectedDetector`, provenance conventions); existing scenarios that lack recorded response text are not retrofitted in this feature.

## Complexity Tracking

> No constitution violations — section intentionally empty.
