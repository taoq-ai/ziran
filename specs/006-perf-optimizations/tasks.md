# Tasks: Performance Optimizations

**Input**: Design documents from `/specs/006-perf-optimizations/`
**Prerequisites**: plan.md (required), spec.md (required), research.md, data-model.md

**Tests**: Not explicitly requested. Existing tests must continue to pass (FR-008).

**Organization**: Tasks grouped by user story. US1 and US2 share a foundational phase since US2 builds directly on the singleton factory introduced in US1.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

---

## Phase 1: Foundational (CSafeLoader + Singleton Factory)

**Purpose**: Core changes to `library.py` that enable all downstream user stories

- [x] T001 [US1] Switch YAML parser from `safe_load` to CSafeLoader with fallback in `ziran/application/attacks/library.py` (line 325)
- [x] T002 [US2] Add `get_attack_library()` singleton factory function after the `AttackLibrary` class definition in `ziran/application/attacks/library.py`
- [x] T003 [US2] Export `get_attack_library` from module `__all__` (if exists) in `ziran/application/attacks/library.py`

**Checkpoint**: `library.py` has CSafeLoader and singleton factory. Existing tests should still pass since no callers changed yet.

---

## Phase 2: User Story 2 - Cached Library Instances (Priority: P1)

**Goal**: Update all default-config callers to use the singleton factory, eliminating redundant YAML parsing.

**Independent Test**: Run `pytest tests/ -x` — all tests pass. Verify only 1 full library parse occurs for default-config callers.

### Implementation for User Story 2

- [x] T004 [P] [US2] Update `benchmarks/inventory.py` (line 29): replace `AttackLibrary()` with `get_attack_library()`
- [x] T005 [P] [US2] Update `benchmarks/owasp_coverage.py` (line 35): replace `AttackLibrary()` with `get_attack_library()`
- [x] T006 [P] [US2] Update `benchmarks/benchmark_comparison.py` (line 506): replace `AttackLibrary()` with `get_attack_library()`
- [x] T007 [P] [US2] Update `benchmarks/comparative_analysis.py` (line 205): replace `AttackLibrary()` with `get_attack_library()`
- [x] T008 [P] [US2] Update `benchmarks/utility_metrics.py` (line 45): replace `AttackLibrary()` with `get_attack_library()`
- [x] T009 [P] [US2] Update `benchmarks/performance_metrics.py` (lines 94, 103, 159): use `get_attack_library()` for filter and throughput benchmarks. Keep `AttackLibrary()` in `_bench_library_init()` (line 86)
- [x] T010 [US2] Update `ziran/application/agent_scanner/scanner.py` (line 149): use `get_attack_library()` as fallback when no library is provided

**Checkpoint**: All default-config callers use the singleton. Only `_bench_library_init()` creates fresh instances.

---

## Phase 3: User Story 3 - Faster CI Benchmark Execution (Priority: P2)

**Goal**: Reduce benchmark iterations from 3 to 1 to cut CI execution time.

**Independent Test**: Run performance benchmark module and confirm it completes in under 60 seconds locally.

### Implementation for User Story 3

- [x] T011 [US3] Reduce default `iterations` parameter from 3 to 1 in `_measure_operation()` in `benchmarks/performance_metrics.py` (line 29)

**Checkpoint**: Benchmark suite runs significantly faster. Combined with singleton (Phase 2), total benchmark time drops from minutes to seconds.

---

## Phase 4: User Story 4 - Scalable Chain Analysis (Priority: P2)

**Goal**: Optimize the O(T^2) indirect chain detection to handle 50+ tools efficiently.

**Independent Test**: Run chain analyzer tests (`pytest tests/ -k "chain" -x`) and confirm identical results with improved performance.

### Implementation for User Story 4

- [x] T012 [US4] Add keyword pre-index computation before the nested loop in `_find_indirect_chains()` in `ziran/application/knowledge_graph/chain_analyzer.py` (lines 198-257): extract keywords from all tool IDs, build reverse mapping from pattern keywords to candidate tool sets, iterate only over matching pairs
- [x] T013 [US4] Add `nx.has_path()` reachability guard before `nx.all_simple_paths()` call in `_find_indirect_chains()` in `ziran/application/knowledge_graph/chain_analyzer.py` (line ~224)

**Checkpoint**: Chain analysis produces identical results but runs significantly faster for large tool sets.

---

## Phase 5: Polish & Verification

**Purpose**: Quality gates and final validation

- [x] T014 Run `ruff check .` and `ruff format --check .` — fix any violations
- [x] T015 Run `python -m mypy ziran/` — fix any type errors
- [x] T016 Run `pytest tests/ -x -m "not integration"` — confirm all unit tests pass (1814 passed)
- [x] T017 Run `pytest tests/ -k "chain" -x` — confirm chain analyzer results unchanged (85 passed)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1 (Foundational)**: No dependencies — start immediately
- **Phase 2 (US2 - Callers)**: Depends on T002 (singleton factory) from Phase 1
- **Phase 3 (US3 - Iterations)**: Depends on Phase 2 (callers use singleton before reducing iterations)
- **Phase 4 (US4 - Chain Analyzer)**: No dependency on Phases 2-3 — can run in parallel after Phase 1
- **Phase 5 (Polish)**: Depends on all previous phases

### User Story Dependencies

- **US1 (P1)**: Standalone — CSafeLoader change in T001
- **US2 (P1)**: Depends on T002 (singleton factory) — then all caller updates (T004-T010) are parallel
- **US3 (P2)**: Depends on US2 completion (singleton must be in place before reducing iterations)
- **US4 (P2)**: Independent of US2/US3 — only requires Phase 1 foundational

### Parallel Opportunities

- T004-T009 can all run in parallel (different benchmark files)
- T012-T013 can run sequentially within chain_analyzer.py but in parallel with Phase 2/3
- Phase 4 (chain analyzer) is fully independent from Phases 2-3 (benchmark changes)

---

## Parallel Example: Phase 2 (Caller Updates)

```bash
# All benchmark caller updates can run in parallel:
Task: "Update benchmarks/inventory.py — replace AttackLibrary() with get_attack_library()"
Task: "Update benchmarks/owasp_coverage.py — replace AttackLibrary() with get_attack_library()"
Task: "Update benchmarks/benchmark_comparison.py — replace AttackLibrary() with get_attack_library()"
Task: "Update benchmarks/comparative_analysis.py — replace AttackLibrary() with get_attack_library()"
Task: "Update benchmarks/utility_metrics.py — replace AttackLibrary() with get_attack_library()"
Task: "Update benchmarks/performance_metrics.py — use get_attack_library() for filter/throughput"
```

---

## Implementation Strategy

### MVP First (User Stories 1 + 2)

1. Complete Phase 1: CSafeLoader + singleton factory
2. Complete Phase 2: Update all callers
3. **STOP and VALIDATE**: Run tests, confirm library init is 5x+ faster and singleton works
4. This alone delivers the majority of performance improvement

### Incremental Delivery

1. Phase 1 + Phase 2 → Library parsing 10x faster + singleton eliminates redundancy (MVP)
2. Add Phase 3 → Benchmark iterations reduced, CI time drops further
3. Add Phase 4 → Chain analysis scales to 50+ tools
4. Phase 5 → All quality gates pass

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- T001 is the highest-leverage single change (1 line, 10x speedup)
- T002 is the second highest-leverage change (singleton eliminates 6+ redundant inits)
- Phase 4 is independent and can be done in any order relative to Phases 2-3
- Commit after each phase or logical group
