# Tasks: argument provenance in the side-effect detector

**Spec**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md)

## Phase 1: tests first

- [x] T001 Write `tests/fixtures/detection/study_v1_verdicts.json` from the `study-v1` export (plan.md)
- [x] T002 Write `tests/unit/test_side_effect_provenance.py`: typing, T3, P1, mix-ups, malformed keys, record, CWE-532
- [x] T003 Write `tests/integration/test_detection_study_v1_equality.py`: study-v1 equality, benign-task items
- [x] T004 Run both red (module missing; `DetectionExample` has no `metadata`)

## Phase 2: implementation

- [x] T005 Add `ziran/application/detectors/provenance.py` (verbs verbatim from the runbook appendix)
- [x] T006 Call `provenance()` first in `SideEffectDetector.detect`; study-v1 path when not applicable
- [x] T007 Add `metadata` and `message_index` to the dataset schema; pass them in both benchmark harnesses
- [x] T008 Add `gen_benign_task` to `generate_dataset.py`; regenerate (six new items, existing files unchanged)
- [x] T009 Run both test files green

## Phase 3: checks and records

- [x] T010 Synthetic parity against the frozen dev probe (plan.md)
- [x] T011 Rebuild `benchmarks/results/detection_accuracy_baseline.json` and the docs row
- [x] T012 Confirm the four frozen files are byte-identical to `study-v1`
- [x] T013 ruff check, ruff format, mypy strict, the full test suite with coverage
- [x] T014 Record the change in `CLAUDE.md`

## Phase 4: fix round 1 (gates at 57381bc)

- [x] T015 Return not_applicable before any shape check when neither task nor payload is given; ignore blank payload strings
- [x] T016 Tests for the long-value branch, empty and bool atoms, P1 on read calls, both payload-guard clauses, the boundaries and the hit score
- [x] T017 Commit a seeded parity test against a copy of the frozen probe (`tests/unit/test_provenance_probe_parity.py`)
- [x] T018 Spec: the error path per caller; docs: the reserved metadata keys

## Phase 5: fix round 2 (gates at 0dbb7ff)

- [x] T019 Treat `payload: null` as absent
- [x] T020 Match the payload as one joined text, as the probe does; test a value spanning two strings
- [x] T021 Parity: the probe's own verb lists, two-injection and two-user-message logs, the log shapes stated
- [x] T022 Test a write-then-read name (`update_status`)
