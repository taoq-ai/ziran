# Tasks: the hybrid's three model jobs on the seam

**Input**: [spec.md](spec.md), [plan.md](plan.md)

## Phase 1: tests first

- [x] T001 Copy the spike prompts into `ziran/application/hybrid/prompts/`; write plausibility v0
- [x] T002 Render the spike fixture with the spike's own `render_trace` (`tests/fixtures/hybrid/`)
- [x] T003 Job tests (acceptance 1 and 2, forms, causes, LLM01 cases, repeat key) in `tests/unit/test_hybrid_jobs.py`
- [x] T004 Differential test of `_evidence` against develop's in `tests/unit/test_provenance_extraction.py`
- [x] T005 Settings and CLI tests in `tests/unit/test_hybrid_settings.py`
- [x] T006 Run the new tests red

## Phase 2: implementation

- [x] T007 `_kinds` and `evidence_values` in `provenance.py`
- [x] T008 `decide()`: unit-aware parse, `UnusableReplyError`, `repeat`
- [x] T009 `request_key(repeat=)` and `RecordReplayClient.complete(repeat=)`
- [x] T010 `ziran/application/hybrid/jobs.py`
- [x] T011 `DetectorThresholds` fields; `scan --hybrid-route-share`; `audit --typed-chains`; `agent_chains(typed=, role_overrides=)`

## Phase 3: checks

- [x] T012 New tests green; ruff, ruff format, mypy, the full unit and integration suites
- [x] T013 Detection regression and benchmark regression check
- [x] T014 Mutants in scratch copies, with an unmutated control
- [x] T015 Update `CLAUDE.md`
