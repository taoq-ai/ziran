# Implementation Plan: Eliminate indicator-matching false positives in the detection pipeline

**Branch**: `fix/027-detector-indicator-false-positives` | **Date**: 2026-06-23 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/027-detector-indicator-false-positives/spec.md`

## Summary

The `IndicatorDetector` marks benign agent responses as attacks when topical
words merely appear in capability descriptions or refusals (reported: a
data-analyst agent listing `search_database, send_email_report` flagged for data
exfiltration with matched indicators `email, data`). Fix in three layers:
(1) add a capability/self-description context guard to `_is_genuine_match`;
(2) default `indicator_matchtype` to word-boundary; (3) curate bare topical
single-word `success_indicators` across all vector YAMLs into evidence-bearing
indicators. Verified by new regression/guard unit tests and the spec-021
detection-accuracy benchmark (precision up, recall unchanged).

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary Dependencies**: Pydantic v2 (entities/config), PyYAML (vector loading), `re` (stdlib). No new dependencies.
**Storage**: N/A — attack vectors are YAML files under `ziran/application/attacks/vectors/`; benchmark artifacts under `benchmarks/`.
**Testing**: pytest (`@pytest.mark.unit`, `@pytest.mark.integration`); existing `tests/unit/test_detectors.py`, `tests/integration/test_detection_regression.py`.
**Target Platform**: Linux/macOS CLI + library.
**Project Type**: Single project (hexagonal: domain / application / infrastructure / interfaces).
**Performance Goals**: Detection is in-process string matching; change is O(n) over response length — no measurable regression.
**Constraints**: mypy strict, ruff clean, line length 100, coverage ≥ 85%.
**Scale/Scope**: One detector module, one config default, ~33 vector YAML files, plus tests + benchmark dataset.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I. Hexagonal Architecture** — ✅ Changes confined to `application/detectors/` (use-case logic) and YAML vector data; no cross-layer dependency added. Domain entities (`DetectorResult`, `DetectionVerdict`) unchanged.
- **II. Type Safety** — ✅ New helpers are fully annotated; no new dicts for domain data. mypy strict must pass.
- **III. Test Coverage** — ✅ New unit tests (guard, word-boundary, FP repro) + integration regression + positive (genuine-disclosure) test. Coverage ≥ 85%.
- **IV. Async-First** — ✅ No I/O introduced; detector matching stays synchronous as it already is (pipeline `evaluate` remains async).
- **V. Extensibility via Adapters** — ✅ New attack-vector behavior expressed as YAML edits; detector keeps the existing `Detector` interface.
- **VI. Simplicity** — ✅ Reuses the existing guard pattern (`_NEGATION_TOKENS`, `_DESCRIPTIVE_CONTEXT_PHRASES`, `_is_descriptive_context`); adds one analogous tuple + helper. No new abstractions.

No violations → Complexity Tracking not required.

## Project Structure

### Documentation (this feature)

```text
specs/027-detector-indicator-false-positives/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── checklists/
│   └── requirements.md  # Spec quality checklist
└── tasks.md             # Phase 2 output (/speckit.tasks)
```

### Source Code (repository root)

```text
ziran/application/detectors/
├── indicator.py         # ADD capability-context guard to _is_genuine_match
└── pipeline.py          # CHANGE DetectorConfig.indicator_matchtype default "str" → "word"

ziran/application/attacks/vectors/
└── *.yaml               # CURATE bare topical single-word success_indicators (≈33 files)

tests/
├── unit/test_detectors.py              # FP repro, capability-guard, word-boundary, positive tests
└── integration/test_detection_regression.py  # Quanta should-NOT-flag scenario

benchmarks/ground_truth/detection/      # ADD benign capability-description cases; re-run benchmark
```

**Structure Decision**: Single-project hexagonal layout (existing). All logic
changes live in the application layer (`detectors/`); attack knowledge stays as
YAML data per Constitution principle V; tests mirror the existing structure.

## Complexity Tracking

No constitution violations — section intentionally empty.
