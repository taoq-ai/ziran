# Tasks: Extract Shared Adapter & Strategy Factories

**Input**: Design documents from `/specs/002-extract-shared-factories/`
**Prerequisites**: plan.md (required), spec.md (required), research.md, data-model.md

**Tests**: Included — the constitution requires unit tests for all business logic (application layer).

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **Source**: `ziran/` at repository root (hexagonal layout)
- **Tests**: `tests/` at repository root

---

## Phase 1: Setup

**Purpose**: Create the new factory module with scaffolding

- [x] T001 Create `ziran/application/factories.py` with module docstring, `__all__` exports, and imports for domain types (`TargetConfig`, `ProtocolType`, `BaseAgentAdapter`, `BaseLLMClient`)

---

## Phase 2: Foundational (Extract Helpers)

**Purpose**: Move private helper functions from CLI to factories — MUST complete before user story tasks

**⚠️ CRITICAL**: These helpers are used by the main factory functions in Phase 3

- [x] T002 Move `_load_python_object()` from `ziran/interfaces/cli/main.py` to `ziran/application/factories.py` — replace `click.ClickException` with `FileNotFoundError`, `ImportError`, and `ValueError`
- [x] T003 Move `_load_bedrock_config()` from `ziran/interfaces/cli/main.py` to `ziran/application/factories.py` — replace `click.ClickException` with `FileNotFoundError` and `ValueError`

**Checkpoint**: Helpers available in factories module, CLI still uses its own copies (no breakage yet)

---

## Phase 3: User Story 1 — CLI Scan Works Identically After Refactor (Priority: P1) 🎯 MVP

**Goal**: Extract all three factory functions, update CLI to use them, zero behavior change

**Independent Test**: Run full existing test suite — all tests pass, CLI scan commands produce identical results

### Tests for User Story 1

- [x] T004 [P] [US1] Write unit tests for `load_remote_adapter()` in `tests/unit/application/test_factories.py` — test HTTP adapter creation from target YAML, browser adapter creation with protocol override, missing file raises `FileNotFoundError`, invalid YAML raises `ValueError`
- [x] T005 [P] [US1] Write unit tests for `load_agent_adapter()` in `tests/unit/application/test_factories.py` — test each framework (langchain, crewai, bedrock, agentcore), unsupported framework raises `ValueError`, missing dependency raises `ImportError`
- [x] T006 [P] [US1] Write unit tests for `build_strategy()` in `tests/unit/application/test_factories.py` — test fixed/adaptive/llm-adaptive creation, llm-adaptive without llm_client falls back to adaptive with `logging.warning`

### Implementation for User Story 1

- [x] T007 [P] [US1] Implement `load_remote_adapter(target_path: str, protocol_override: str | None = None) -> BaseAgentAdapter` in `ziran/application/factories.py` — extract from CLI's `_load_remote_adapter()`, remove Rich console output, replace `click.ClickException` with standard exceptions
- [x] T008 [P] [US1] Implement `load_agent_adapter(framework: str, agent_path: str) -> BaseAgentAdapter` in `ziran/application/factories.py` — extract from CLI's `_load_agent_adapter()`, replace `click.ClickException` with standard exceptions, use moved `_load_python_object` and `_load_bedrock_config` helpers
- [x] T009 [P] [US1] Implement `build_strategy(strategy_name: str, stop_on_critical: bool, llm_client: Any | None = None) -> Any` in `ziran/application/factories.py` — extract from CLI's `_build_strategy()`, replace `console.print` warning with `logging.warning()`
- [x] T010 [US1] Update `ziran/interfaces/cli/main.py` — replace `_load_remote_adapter()` calls with `from ziran.application.factories import load_remote_adapter`, wrap calls in try/except to convert `ValueError`/`ImportError`/`FileNotFoundError` to `click.ClickException`, move Rich console output (target/protocol/auth display) to CLI after factory call
- [x] T011 [US1] Update `ziran/interfaces/cli/main.py` — replace `_load_agent_adapter()` calls with `from ziran.application.factories import load_agent_adapter`, wrap calls in try/except for `click.ClickException` conversion
- [x] T012 [US1] Update `ziran/interfaces/cli/main.py` — replace `_build_strategy()` calls with `from ziran.application.factories import build_strategy`, wrap calls in try/except for `click.ClickException` conversion
- [x] T013 [US1] Remove private functions `_load_remote_adapter`, `_load_agent_adapter`, `_build_strategy`, `_load_python_object`, `_load_bedrock_config` from `ziran/interfaces/cli/main.py`
- [x] T014 [US1] Run quality gates: `ruff check .`, `ruff format --check .`, `mypy ziran/`, `pytest --cov=ziran` — fix any issues

**Checkpoint**: CLI works identically, all tests pass, factory module is the single source of truth

---

## Phase 4: User Story 2 — Web UI Backend Reuses Factories (Priority: P2)

**Goal**: Verify the factory module has a clean public API importable without CLI dependencies

**Independent Test**: Import `ziran.application.factories` from a standalone script — no `click` or `rich` in the import chain

### Implementation for User Story 2

- [x] T015 [US2] Write an import isolation test in `tests/unit/application/test_factories.py` — verify that importing `ziran.application.factories` does not transitively import `click`, `rich`, or anything from `ziran.interfaces`
- [x] T016 [US2] Add `__all__` to `ziran/application/factories.py` exporting `load_remote_adapter`, `load_agent_adapter`, `build_strategy` as the public API

**Checkpoint**: Factory module is fully reusable by any interface layer

---

## Phase 5: User Story 3 — Hexagonal Architecture Compliance (Priority: P3)

**Goal**: Verify factories only depend on domain and infrastructure layers — no interface-layer imports

**Independent Test**: Static analysis of import graph confirms inward-only dependencies

### Implementation for User Story 3

- [x] T017 [US3] Write an architecture test in `tests/unit/application/test_factories.py` — use `importlib` or AST to verify `ziran/application/factories.py` has zero imports from `ziran.interfaces`
- [x] T018 [US3] Verify the factory module's type annotations use domain types (`BaseAgentAdapter`) not infrastructure concrete types in return signatures where possible

**Checkpoint**: Hexagonal architecture validated for the factory module

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Final validation and cleanup

- [x] T019 Run full quality gate suite: `ruff check .`, `ruff format --check .`, `mypy ziran/`, `pytest --cov=ziran` — all must pass
- [x] T020 Verify quickstart.md examples work by testing imports and function signatures match documentation
- [x] T021 Update spec.md status from Draft to Active

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — start immediately
- **Foundational (Phase 2)**: Depends on Phase 1
- **User Story 1 (Phase 3)**: Depends on Phase 2 — BLOCKS Stories 2 and 3
- **User Story 2 (Phase 4)**: Depends on User Story 1 (needs factory module to exist)
- **User Story 3 (Phase 5)**: Depends on User Story 1 (needs factory module to exist)
- **Polish (Phase 6)**: Depends on all stories complete

### User Story Dependencies

- **User Story 1 (P1)**: Core refactor — must be done first (creates the factory module)
- **User Story 2 (P2)**: Can start after US1 — validates API cleanliness
- **User Story 3 (P3)**: Can start after US1 — validates architecture compliance. Can run in parallel with US2.

### Within User Story 1

- Tests (T004-T006) can all run in parallel [P]
- Factory implementations (T007-T009) can all run in parallel [P] — different functions in same file
- CLI updates (T010-T012) are sequential — same file, interdependent changes
- Removal (T013) depends on all CLI updates
- Quality gates (T014) must be last

### Parallel Opportunities

- T004, T005, T006 — all test files can be written in parallel
- T007, T008, T009 — factory functions are independent of each other
- T015 and T017 — US2 and US3 tests are independent, different concerns

---

## Parallel Example: User Story 1

```bash
# Launch all factory tests together:
Task T004: "Unit tests for load_remote_adapter in tests/unit/application/test_factories.py"
Task T005: "Unit tests for load_agent_adapter in tests/unit/application/test_factories.py"
Task T006: "Unit tests for build_strategy in tests/unit/application/test_factories.py"

# Launch all factory implementations together:
Task T007: "Implement load_remote_adapter in ziran/application/factories.py"
Task T008: "Implement load_agent_adapter in ziran/application/factories.py"
Task T009: "Implement build_strategy in ziran/application/factories.py"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup (T001)
2. Complete Phase 2: Foundational (T002-T003)
3. Complete Phase 3: User Story 1 (T004-T014)
4. **STOP and VALIDATE**: Run full test suite, verify CLI behavior unchanged
5. Ready for review/merge

### Incremental Delivery

1. Setup + Foundational → Helpers extracted
2. User Story 1 → Full refactor done, CLI working → **MVP complete**
3. User Story 2 → API isolation validated
4. User Story 3 → Architecture compliance confirmed
5. Polish → All gates pass, docs updated

---

## Notes

- [P] tasks = different files or independent functions, no dependencies
- [Story] label maps task to specific user story for traceability
- Total tasks: 21
- US1: 11 tasks (core refactor), US2: 2 tasks (API validation), US3: 2 tasks (architecture)
- Setup: 1 task, Foundational: 2 tasks, Polish: 3 tasks
- This is a pure refactor — no new features, no new data, no new dependencies
