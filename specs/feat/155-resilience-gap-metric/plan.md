# Implementation Plan: Resilience Gap Metric

**Branch**: `feat/155-resilience-gap-metric` | **Date**: 2026-03-20 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/004-resilience-gap-metric/spec.md`

## Summary

Extend the existing `ResilienceMetrics` model with baseline performance, under-attack performance, and resilience gap delta fields. Update `compute_resilience()` to calculate these values. Surface the metric in reports and close GAP-09 in benchmarks.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix: 3.11, 3.12, 3.13)
**Primary Dependencies**: Pydantic (models), PyYAML (vector definitions)
**Storage**: N/A (in-memory computation, JSON output)
**Testing**: pytest with markers (@pytest.mark.unit)
**Target Platform**: CLI tool (cross-platform)
**Project Type**: Library/CLI
**Performance Goals**: N/A (metric computation is trivial)
**Constraints**: Must maintain backward compatibility with existing ResilienceMetrics consumers
**Scale/Scope**: 3 new fields on ResilienceMetrics, ~20 lines in compute_resilience, benchmark updates

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Gate | Status | Notes |
|------|--------|-------|
| Hexagonal Architecture | PASS | Changes are in domain (entities) and benchmarks (scripts) — correct layers |
| Type Safety | PASS | New fields use Pydantic Field with float type, ge/le constraints |
| Test Coverage | PASS | Will add unit tests for new fields and computation |
| Async-First | N/A | Pure computation, no I/O |
| Extensibility | PASS | No new interfaces needed, extending existing model |
| Simplicity | PASS | 3 new fields + formula update, minimal complexity |

## Project Structure

### Documentation (this feature)

```text
specs/feat/155-resilience-gap-metric/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
└── spec.md              # Feature specification
```

### Source Code (repository root)

```text
ziran/
├── domain/
│   └── entities/
│       └── phase.py              # ResilienceMetrics model + compute_resilience()
├── interfaces/
│   └── cli/
│       └── reports.py            # Report output (if resilience gap display needed)
benchmarks/
├── benchmark_comparison.py       # AILuminate metric update
├── gap_status.py                 # GAP-09 closure
└── generate_all.py               # Regenerate reports
tests/
└── unit/
    └── test_resilience_metrics.py  # New/extended tests
```

**Structure Decision**: Changes touch the domain entity layer (ResilienceMetrics), benchmark scripts, and tests. No new modules needed.
