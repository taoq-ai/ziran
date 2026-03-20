# Tasks: Pre-compile Regex Patterns in Static Analysis

**Input**: Design documents from `/specs/003-precompile-regex-patterns/`
**Prerequisites**: plan.md (required), spec.md (required), research.md, data-model.md

**Tests**: Included — the constitution requires unit tests for all business logic (application layer).

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **Source**: `ziran/application/static_analysis/` at repository root
- **Tests**: `tests/unit/application/` at repository root

---

## Phase 1: Setup

**Purpose**: No setup needed — existing files are being modified

(No tasks — this feature modifies existing files only)

---

## Phase 2: Foundational (Pre-compile Pattern Fields)

**Purpose**: Add compiled pattern fields to all config models — MUST complete before user stories

- [x] T001 [P] Add `compiled` field to `PatternRule` via `model_validator(mode="after")` in `ziran/application/static_analysis/config.py` — compile `self.pattern` into `re.Pattern`, store as excluded field
- [x] T002 [P] Add `compiled_patterns` property or field to `CheckDefinition` in `ziran/application/static_analysis/config.py` — derive from `self.patterns` list of `PatternRule` objects
- [x] T003 [P] Add `compiled_pattern` field to `DangerousToolCheck` via `model_validator(mode="after")` in `ziran/application/static_analysis/config.py` — compile `self.pattern` into `re.Pattern`
- [x] T004 [P] Add `compiled_tool_pattern` and `compiled_validation_pattern` fields to `InputValidationCheck` via `model_validator(mode="after")` in `ziran/application/static_analysis/config.py` — compile both pattern strings

**Checkpoint**: All config models have pre-compiled pattern fields

---

## Phase 3: User Story 1 — Faster Static Analysis on Large Codebases (Priority: P1) 🎯 MVP

**Goal**: Eliminate redundant regex compilations by using pre-compiled patterns in the analyzer

**Independent Test**: Run static analysis on a multi-file directory and verify each pattern is compiled once

### Tests for User Story 1

- [x] T005 [P] [US1] Write unit tests for pre-compiled patterns in `tests/unit/application/test_precompiled_patterns.py` — test that `PatternRule`, `CheckDefinition`, `DangerousToolCheck`, and `InputValidationCheck` have compiled patterns after construction; test invalid regex raises error at construction time; test patterns survive config merging
- [x] T006 [P] [US1] Write unit test verifying no `re.compile()` calls happen during analysis in `tests/unit/application/test_precompiled_patterns.py` — mock `re.compile` during `_run_check` / `_run_dangerous_tool_checks` / `_check_input_validation` calls and assert it is not called

### Implementation for User Story 1

- [x] T007 [US1] Update `_run_check()` in `ziran/application/static_analysis/analyzer.py` — replace `compiled = [re.compile(p.pattern) for p in check.patterns]` with `compiled = check.compiled_patterns` (or equivalent using `PatternRule.compiled`)
- [x] T008 [US1] Update `_run_dangerous_tool_checks()` in `ziran/application/static_analysis/analyzer.py` — replace `compiled = [(re.compile(c.pattern), c) for c in checks]` with `compiled = [(c.compiled_pattern, c) for c in checks]`
- [x] T009 [US1] Update `_check_input_validation()` in `ziran/application/static_analysis/analyzer.py` — replace `re.search(check.tool_definition_pattern, ...)` and `re.search(check.validation_pattern, ...)` with `check.compiled_tool_pattern.search(...)` and `check.compiled_validation_pattern.search(...)`
- [x] T010 [US1] Remove `import re` from `ziran/application/static_analysis/analyzer.py` if no longer needed (verify no other uses remain)

**Checkpoint**: Static analysis uses pre-compiled patterns. All existing tests pass.

---

## Phase 4: User Story 2 — Existing Tests and Integrations Continue Working (Priority: P2)

**Goal**: Verify zero behavior change

**Independent Test**: Run full test suite — all tests pass without modification

### Implementation for User Story 2

- [x] T011 [US2] Run existing static analysis tests: `pytest tests/unit/application/test_static_analysis.py -v` — verify all pass without any assertion changes
- [x] T012 [US2] Run full test suite: `pytest` — verify no regressions anywhere

**Checkpoint**: All tests pass, zero behavior change confirmed

---

## Phase 5: Polish & Cross-Cutting Concerns

**Purpose**: Final validation

- [x] T013 Run quality gates: `ruff check .`, `ruff format --check .`, `mypy ziran/` — fix any issues
- [x] T014 Run full test suite with coverage: `pytest --cov=ziran` — verify coverage >= 85%

---

## Dependencies & Execution Order

### Phase Dependencies

- **Foundational (Phase 2)**: T001-T004 all parallel — add compiled fields to config models
- **User Story 1 (Phase 3)**: Depends on Phase 2 — uses compiled fields in analyzer
- **User Story 2 (Phase 4)**: Depends on Phase 3 — validates zero behavior change
- **Polish (Phase 5)**: Depends on all stories complete

### Parallel Opportunities

- T001, T002, T003, T004 — all modify different classes in the same file but are logically independent
- T005, T006 — test files can be written in parallel with implementation
- T007, T008, T009 — modify different functions in analyzer.py (sequential recommended)

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 2: Add compiled fields to config models (T001-T004)
2. Complete Phase 3: Use compiled patterns in analyzer (T005-T010)
3. **STOP and VALIDATE**: Run existing test suite
4. Ready for review/merge

### Incremental Delivery

1. Foundational → Config models have compiled patterns
2. User Story 1 → Analyzer uses pre-compiled patterns → **MVP complete**
3. User Story 2 → Full regression validation
4. Polish → All gates pass

---

## Notes

- [P] tasks = different files or independent functions, no dependencies
- [Story] label maps task to specific user story for traceability
- Total tasks: 14
- US1: 6 tasks (core optimization), US2: 2 tasks (regression validation)
- Foundational: 4 tasks, Polish: 2 tasks
- This is a pure optimization — no new features, no new external dependencies
- All T001-T004 touch the same file (config.py) but different classes — implement sequentially for safety
