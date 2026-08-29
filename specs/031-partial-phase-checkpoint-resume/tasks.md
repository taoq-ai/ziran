# Tasks: Partial-phase checkpoint resume

**Input**: Design documents from `/specs/031-partial-phase-checkpoint-resume/`
**Prerequisites**: plan.md, spec.md

**Tests**: Included - the spec (FR-008, SC-001..SC-003) requires crash/resume and throttle tests (TDD).

**Branch**: `031-partial-phase-checkpoint-resume` (off `develop`)

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: US1 / US2 / US3 from spec.md

## Path Conventions

Single-project hexagonal layout: source in `ziran/`, tests in `tests/`.

---

## Phase 1: Setup

- [ ] T001 Confirm branch `031-partial-phase-checkpoint-resume` is checked out off latest `develop`. Re-read `CheckpointManager` (checkpoint.py), `PhaseExecutor.execute` (phase_executor.py), and the between-phase save in `scanner.run_campaign` to confirm `tested_vector_ids`/`attack_results` are already live-updated and that resume already excludes tested vectors.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: The throttle helper every flush decision depends on.

- [ ] T002 [US2] Write a failing unit test in `tests/unit/application/test_checkpoint.py` for `FlushThrottle`: with an injected clock, assert `record()` returns False until the N-th completion (then resets), and returns True when >= K seconds elapsed even before N completions. (Watch it fail: helper does not exist yet.)
- [ ] T003 [US2] Add `FlushThrottle(max_completions, max_seconds, *, clock=time.monotonic)` to `ziran/application/agent_scanner/checkpoint.py` with `record() -> bool` (increments, returns/consumes a due flush on either bound). Minimum code to green T002.

**Checkpoint**: Throttle bounds proven by unit test.

---

## Phase 3: User Story 1 - Resume a crashed phase (P1) MVP

**Goal**: A mid-phase crash resumes without re-running completed vectors.

**Independent Test**: Crash after ~30% of a phase, resume, assert only the remaining ~70% run.

- [ ] T004 [US1] Write a failing unit test in `tests/unit/application/test_phase_executor_checkpoint.py`: run `PhaseExecutor.execute` (stub library/executor/graph, `max_concurrent=1`) with an `on_vector_complete` callback and assert it is invoked once per completed vector, after the vector is added to the shared `tested_vector_ids`. (Fails: param does not exist.)
- [ ] T005 [US1] Add `on_vector_complete: Callable[[], None] | None = None` to `PhaseExecutor.execute` and call it inside the existing result `async with lock` block, after `tested_vector_ids.add(result.vector_id)`. Green T004. Keep default `None` behaviour identical to today (FR-007).
- [ ] T006 [US1] Write a failing integration test in `tests/integration/test_partial_phase_resume.py`: 10 stub vectors, `max_concurrent=1`, flush every completion; a stub executor that records executed IDs and raises a `BaseException`-derived crash on the 4th vector. Run 1 crashes; assert the on-disk checkpoint holds exactly the 3 completed IDs. Run 2 (fresh graph/executor, `tested_vector_ids` loaded from the checkpoint) executes only the remaining 7, disjoint from run 1. (Fails until wiring exists.)
- [ ] T007 [US1] Wire a throttled flush callback into `scanner.run_campaign`: build it once before the phase loop (reads live `campaign_id`, `phase_results`, `remaining_phases`, `campaign_tokens`, `self._tested_vector_ids`, `self._attack_results`), gated on `checkpoint_manager` and a `FlushThrottle`; on a due flush call the existing `build_checkpoint` + `save`. Pass it as `on_vector_complete` to `phase_executor.execute`. Green T006.

**Checkpoint**: US1 independently verifiable and green.

---

## Phase 4: User Story 2 - Bounded overhead + CLI (P1)

**Goal**: Throttled writes, configurable interval.

- [ ] T008 [US2] Add `checkpoint_flush_interval: float = <default>` to `run_campaign`; use it as the `FlushThrottle` seconds bound (completion-count bound is a module default constant).
- [ ] T009 [US2] Add `--checkpoint-flush-interval` (FLOAT, default matching T008) to the `scan` command in `ziran/interfaces/cli/main.py` and pass it through to `run_campaign`. Help text: batched incremental checkpoint flush interval in seconds.

**Checkpoint**: Operator can tune the flush interval; default keeps overhead bounded.

---

## Phase 5: User Story 3 - Backwards compatibility (P2)

**Goal**: Old checkpoints still load and resume.

- [ ] T010 [US3] Add a unit test in `tests/unit/application/test_checkpoint.py` loading a checkpoint dict with only the pre-existing fields (no incremental-specific fields) and asserting it validates and its `tested_vector_ids` drive exclusion. (Confirms FR-006 - expected to pass since no format change; keep as a guard.)

**Checkpoint**: Compatibility guarded by test.

---

## Phase 6: Polish & Quality Gates

- [ ] T011 Author `docs/guides/long-running-campaigns.md`: when to use `--resume`, how partial-phase resume works, `--checkpoint-flush-interval` guidance, and the observed overhead figure from the T006 integration test.
- [ ] T012 Run all quality gates: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`, `uv run pytest --cov=ziran` (coverage >= 85%). Fix any failures.

---

## Dependencies & Execution Order

- **Setup (T001)** -> **Foundational (T002-T003)** -> user stories.
- **US1 (T004-T007)**: T005 depends on T004 (TDD); T007 depends on T003 + T005; T006 authored before T007 (fails first), green after T007.
- **US2 (T008-T009)** depends on T003 + T007.
- **US3 (T010)** independent (no format change) - can run any time after T003.
- **Polish (T011-T012)** last; T011 references the T006 overhead figure.

## Parallel Opportunities

- T002 (throttle test) and T004 (callback test) touch different test files and can be authored in parallel.
- T010 is independent of the US1/US2 wiring.

## MVP Scope

US1 (T001-T007) alone delivers the reported capability: resume a crashed phase
without re-running completed vectors. US2 (throttle/CLI) and US3 (compat guard)
complete the overhead budget and upgrade safety.
