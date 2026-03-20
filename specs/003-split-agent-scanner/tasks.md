# Tasks: Split AgentScanner into Focused Modules

**Input**: Design documents from `/specs/003-split-agent-scanner/`
**Prerequisites**: plan.md (required), spec.md (required), research.md, data-model.md

**Tests**: Included — the constitution requires unit tests for all business logic (application layer).

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **Source**: `ziran/application/agent_scanner/` at repository root
- **Tests**: `tests/unit/application/` at repository root

---

## Phase 1: Setup

**Purpose**: Create the new module files with scaffolding

- [x] T001 [P] Create `ziran/application/agent_scanner/progress.py` — move `ProgressEventType` (StrEnum) and `ProgressEvent` (dataclass) from `scanner.py`, add `ProgressEmitter` class with typed emit methods (`campaign_start`, `phase_start`, `attack_start`, `attack_complete`, `phase_complete`, `campaign_complete`) that wrap the optional callback
- [x] T002 [P] Create `ziran/application/agent_scanner/result_builder.py` — add `ResultBuilder` class with static methods `build_phase_result()` and `build_campaign_result()` that construct `PhaseResult` and `CampaignResult` from raw data
- [x] T003 [P] Create `ziran/application/agent_scanner/attack_executor.py` — add `AttackExecutor` class with `async execute()` method, move `_render_prompt()` (static), `_is_error_response()`, and attack invocation logic from `scanner.py`
- [x] T004 Create `ziran/application/agent_scanner/phase_executor.py` — add `PhaseExecutor` class with `async execute_phase()` method that uses `AttackExecutor` and `asyncio.Semaphore` for bounded concurrency

**Checkpoint**: All new module files exist with their class skeletons

---

## Phase 2: Foundational (Extract Logic)

**Purpose**: Move implementation logic from scanner.py into the new modules — MUST complete before user story validation

**⚠️ CRITICAL**: These modules contain the actual logic extracted from scanner.py

- [x] T005 Extract `_execute_attack`, `_invoke_streaming`, `_render_prompt`, `_is_error_response`, and encoding/tactic logic from `scanner.py` into `ziran/application/agent_scanner/attack_executor.py` — replace `click` exceptions with standard exceptions, preserve OpenTelemetry spans, move lazy imports (`PromptEncoder`, `TacticExecutor`, `EncodingType`) here
- [x] T006 Extract `_execute_phase` concurrency logic from `scanner.py` into `ziran/application/agent_scanner/phase_executor.py` — preserve `asyncio.Semaphore` bounded concurrency, phase timeout, and per-attack error handling
- [x] T007 Extract result aggregation logic from `scanner.py` into `ziran/application/agent_scanner/result_builder.py` — move `PhaseResult` construction (trust score, vulnerability counting, token aggregation) and `CampaignResult` assembly (resilience computation, chain analysis, business impacts)
- [x] T008 Extract all `on_progress(ProgressEvent(...))` calls from `scanner.py` into `ziran/application/agent_scanner/progress.py` — `ProgressEmitter` should have one method per event type, each constructing the correct `ProgressEvent` with all required fields

**Checkpoint**: All logic extracted into new modules. scanner.py still has the old code (not yet updated).

---

## Phase 3: User Story 1 — Scan Campaigns Produce Identical Results (Priority: P1) 🎯 MVP

**Goal**: Rewire scanner.py to delegate to sub-modules, zero behavior change

**Independent Test**: Run full existing test suite — all 1670 tests pass without modification

### Tests for User Story 1

- [x] T009 [P] [US1] Write unit tests for `AttackExecutor` in `tests/unit/application/test_attack_executor.py` — test single attack execution with mock adapter, prompt rendering with variables, encoding application, error sentinel detection, streaming invocation path
- [x] T010 [P] [US1] Write unit tests for `PhaseExecutor` in `tests/unit/application/test_phase_executor.py` — test concurrent execution with semaphore bounds, phase timeout, attack failure isolation, progress event emission during phase
- [x] T011 [P] [US1] Write unit tests for `ResultBuilder` in `tests/unit/application/test_result_builder.py` — test PhaseResult construction with trust scores, CampaignResult assembly with token aggregation, resilience computation, empty phase handling
- [x] T012 [P] [US1] Write unit tests for `ProgressEmitter` in `tests/unit/application/test_progress_emitter.py` — test each event type emission, null callback handling (no-op), event data correctness (indices, phase names, timestamps)

### Implementation for User Story 1

- [x] T013 [US1] Rewrite `ziran/application/agent_scanner/scanner.py` to use sub-modules — `AgentScanner.__init__` creates `AttackExecutor`, `PhaseExecutor`, `ProgressEmitter`; `run_campaign` delegates phase execution to `PhaseExecutor`, result assembly to `ResultBuilder`; keep knowledge graph management and `_discover_and_map_capabilities` in scanner; keep `_update_graph_from_phase` in scanner; keep strategy integration in scanner
- [x] T014 [US1] Update `ziran/application/agent_scanner/__init__.py` — re-export `AgentScanner`, `ProgressEventType`, `ProgressEvent`, `AgentScannerError` for backward compatibility; add `__all__` list
- [x] T015 [US1] Run full test suite: `pytest` — all 1670 tests must pass with zero assertion changes
- [x] T016 [US1] Run quality gates: `ruff check .`, `ruff format --check .`, `mypy ziran/` — fix any issues

**Checkpoint**: CLI works identically, all tests pass, scanner.py delegates to sub-modules

---

## Phase 4: User Story 2 — Components Are Independently Testable (Priority: P2)

**Goal**: Verify each module can be instantiated and tested without the full scanner

**Independent Test**: Import and use each sub-module in isolation with mock dependencies

### Implementation for User Story 2

- [x] T017 [US2] Verify `AttackExecutor` is independently instantiable — add a test in `tests/unit/application/test_attack_executor.py` that creates an `AttackExecutor` with only a mock adapter and detector pipeline, executes an attack, and validates the result without any scanner or phase context
- [x] T018 [US2] Verify `PhaseExecutor` is independently instantiable — add a test in `tests/unit/application/test_phase_executor.py` that creates a `PhaseExecutor` with a mock `AttackExecutor`, executes a phase, and validates concurrent execution without the campaign orchestrator
- [x] T019 [US2] Verify `ResultBuilder` is independently usable — add a test in `tests/unit/application/test_result_builder.py` that constructs a `CampaignResult` from hand-crafted phase data without running any attacks
- [x] T020 [US2] Verify `ProgressEmitter` is independently usable — add a test in `tests/unit/application/test_progress_emitter.py` that creates a `ProgressEmitter` with a lambda callback and verifies events are emitted correctly

**Checkpoint**: Each module proven independently testable

---

## Phase 5: User Story 3 — Scanner File Is Under 300 Lines (Priority: P3)

**Goal**: Verify scanner.py is concise and delegates properly

### Implementation for User Story 3

- [x] T021 [US3] Verify `scanner.py` line count is under 300 — add a test in `tests/unit/application/test_scanner_size.py` that reads the file and asserts `len(lines) < 300`
- [x] T022 [US3] Verify no module in `agent_scanner/` exceeds 400 lines — add a test in `tests/unit/application/test_scanner_size.py` that checks all `.py` files in the package
- [x] T023 [US3] Verify scanner.py imports from sub-modules — add a test in `tests/unit/application/test_scanner_size.py` using AST to verify scanner.py imports from `phase_executor`, `attack_executor`, `progress`, `result_builder`

**Checkpoint**: Architecture constraints validated by automated tests

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Final validation and cleanup

- [x] T024 Run full quality gate suite: `ruff check .`, `ruff format --check .`, `mypy ziran/`, `pytest` — all must pass
- [x] T025 Verify quickstart.md examples work by testing imports and function signatures match documentation
- [x] T026 Update spec.md status from Draft to Active

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — T001-T004 all parallel
- **Foundational (Phase 2)**: Depends on Phase 1 — T005 depends on T003, T006 depends on T004, T007 depends on T002, T008 depends on T001
- **User Story 1 (Phase 3)**: Depends on Phase 2 — BLOCKS Stories 2 and 3
- **User Story 2 (Phase 4)**: Depends on User Story 1 (needs refactored scanner)
- **User Story 3 (Phase 5)**: Depends on User Story 1 (needs refactored scanner). Can run parallel with US2.
- **Polish (Phase 6)**: Depends on all stories complete

### Parallel Opportunities

- T001, T002, T003, T004 — all setup files can be created in parallel
- T009, T010, T011, T012 — all test files can be written in parallel
- T017-T020 — US2 verification tests are independent
- T021-T023 — US3 validation tests are independent
- US2 and US3 can run in parallel after US1 completes

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup (T001-T004)
2. Complete Phase 2: Extract logic (T005-T008)
3. Complete Phase 3: User Story 1 (T009-T016)
4. **STOP and VALIDATE**: Run full test suite, verify CLI behavior unchanged
5. Ready for review/merge

### Incremental Delivery

1. Setup + Foundational → Module files with extracted logic
2. User Story 1 → Scanner delegates to sub-modules → **MVP complete**
3. User Story 2 → Independent testability validated
4. User Story 3 → Architecture size constraints validated
5. Polish → All gates pass, docs updated

---

## Notes

- [P] tasks = different files or independent functions, no dependencies
- [Story] label maps task to specific user story for traceability
- Total tasks: 26
- US1: 8 tasks (core refactor), US2: 4 tasks (testability validation), US3: 3 tasks (size validation)
- Setup: 4 tasks, Foundational: 4 tasks, Polish: 3 tasks
- This is a pure refactor — no new features, no new external dependencies
- The key risk is circular imports between scanner ↔ phase_executor ↔ attack_executor — dependency direction must be strictly: scanner → phase_executor → attack_executor
