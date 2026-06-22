# Tasks: Dependency Modernization — Retire Security Dismissals

**Input**: Design documents from `/specs/025-dependency-modernization/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: No new test files — this work changes dependencies + refactors adapters, it adds no new logic. The **existing** adapter/orchestrator tests are the correctness oracle (FR-005); where a migrated API changes a mocked shape (e.g. crewai `kickoff()` now returns `CrewOutput`, not `str`), the existing **test doubles are updated** (T009). The full gate matrix (ruff/format/mypy/pytest at the CI `--cov-fail-under=80` floor + `npm run build`) + the spec-024 `dependency-audit` gate are the regression oracle.

**Organization**: Phases run in **execution order**. Note the priority↔dependency inversion: US1 (P1, the security *outcome*) cannot go green until US2 (P2, the *refactor* that enables it) is done — so US2's phase precedes US1's.

## Path Conventions

Python backend at repo root (`pyproject.toml`, `uv.lock`, `ziran/`); CI in `.github/`; security record in `docs/security/`.

---

## Phase 1: Setup

- [X] T001 Record the target alert disposition from `contracts/target-resolution.md` in the tracking PR: **convert→fixed** (litellm #109/#61/#72/#62/#60, langchain-core #78/#47/#40, langgraph #43, langgraph-checkpoint #42, langchain-openai #70, langchain-text-splitters #69) vs **stays-dismissed** (langchain #108 GHSA-gr75, chromadb #84, diskcache #41), and the verify-case (#82).

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Land the Option-C resolution. **Nothing compiles or tests on the new majors until the lock changes.**

- [X] T002 Relax the declared caps in `pyproject.toml` per `contracts/target-resolution.md`: `crewai>=1.14,<2`, `rich>=13.7,<15`, `litellm>=1.84,<2`, `langchain>=1.0,<2`, `langchain-community>=0.4,<2`, `langchain-openai>=1.0,<2`, `langchain-core>=1.0,<2`, `langgraph>=1.0,<2`.
- [X] T003 Regenerate the lock: `uv lock` (MUST exit 0) then `uv sync --frozen --extra all --group test`; confirm the resolved set matches research R1 (crewai 1.14.7, rich 14.3.4, litellm 1.89.3, openai 2.43, langchain-core 1.4.8, langgraph 1.2.2, langgraph-checkpoint 4.1.1, langchain-openai 1.3.2). Commit `pyproject.toml` + `uv.lock`.

**Checkpoint**: the modern majors are installed; the refactor can begin.

---

## Phase 3: User Story 2 — Refactor the framework integrations (Priority: P2, executes first)

**Goal**: Make the adapters/orchestrator/CLI work on the new majors (per `contracts/adapter-migration.md`).

**Independent Test**: `pytest -k "crewai or langchain or pentest or litellm"` + `mypy ziran/` pass on the new majors, and a representative scan completes.

- [X] T004 [US2] Refactor `ziran/infrastructure/adapters/crewai_adapter.py` for crewai 1.14: handle the `CrewOutput` return from `kickoff()` (extract `.raw`/text into the `AgentResponse`), keep the `asyncio.to_thread(kickoff)` bridge, verify `crew.agents`/`crew.tasks` introspection.
- [X] T005 [P] [US2] Migrate `ziran/infrastructure/adapters/langchain_adapter.py` imports for langchain 1.0: resolve `AgentExecutor` and the `langchain_community.callbacks.manager` import to their new homes (migrate, do not pin back). If import targets move, update the `[[tool.mypy.overrides]]` `ignore_missing_imports` entries in `pyproject.toml` accordingly so `mypy` stays clean.
- [X] T006 [P] [US2] Verify/migrate `ziran/application/pentesting/agent.py` `StateGraph` usage on langgraph 1.2 (`add_node`/`add_edge`/`compile()`/`END`); keep the no-checkpointer compile (preserves the spec-024 reachability property).
- [X] T007 [P] [US2] Verify the 7 `rich` importers render on rich 14 (`Console`/`Table`/`Live`/`Panel`/`Prompt`/`Spinner`/`RichHandler`); fix any broken render call sites (FR-003).
- [X] T008 [P] [US2] Verify `ziran/infrastructure/llm/litellm_client.py` + the adaptive-LLM strategy work on litellm 1.89 / openai 2.x (no direct openai-SDK call sites expected).
- [X] T009 [US2] Update existing test doubles/mocks that assumed the old framework APIs (e.g. `kickoff()` returning a `str`) in `tests/unit/test_langchain_crewai_adapters.py`, `tests/integration/test_crewai_adapter.py`, and the langchain/pentest tests — so they assert the new shapes without weakening coverage.
- [X] T010 [US2] Run the framework-integration suite (`uv run pytest -m "unit or integration" -k "crewai or langchain or pentest or litellm" -v`) + `uv run mypy ziran/`; all green.

**Checkpoint**: the integrations work on the new majors — US1 can now go green.

---

## Phase 4: User Story 1 — Convert the alerts from dismissed to fixed (Priority: P1) 🎯 MVP

**Goal**: Full gates green on the upgraded tree and the litellm + langchain-family advisories resolved by upgrade.

**Independent Test**: the full gate suite + frontend build pass, a representative scan completes, and the targeted alerts are fixed-by-upgrade (not dismissed).

- [X] T011 [US1] Run the full regression oracle and fix any residual drift: `uv run ruff check . && uv run ruff format --check . && uv run mypy ziran/ && uv run pytest --cov=ziran` (CI floor `--cov-fail-under=80`) and `cd ui && npm run build`; spot-check CLI rendering on rich 14 (`ziran library`, `ziran audit <example>`, a scan summary).
- [X] T012 [US1] Confirm the lock no longer carries vulnerable versions of the convert→fixed packages; resolve alert **#82** (langchain LangSmith prompt-pull) — mark fixed if langchain 1.3.2 patches it, else keep it as a not-reachable row with justification.
- [ ] T013 [US1] Reopen the now-fixed dismissed Dependabot alerts via the API (per research R9) so they close as *fixed* on the next default-branch rescan; leave #108/#84/#41 dismissed. NOTE: Dependabot resolves alerts from the **default branch (main)**, so the "fixed" state lands when this reaches `main` via release — not immediately on the merge to `develop` (same timing as spec 024).

**Checkpoint**: ~12 alerts are fixed-by-upgrade; security outcome achieved.

---

## Phase 5: User Story 3 — Reconcile the security records (Priority: P3)

**Goal**: Records reflect "fixed", suppression list shrinks to only the no-fix items.

**Independent Test**: the decision record + pip-audit ignore list contain only the kept-dismissed items; the audit gate passes.

- [X] T014 [US3] Remove the now-fixed rows from `docs/security/risk-acceptances.md` (litellm ×5, langchain-core ×3, langgraph, langgraph-checkpoint, langchain-openai, langchain-text-splitters), keeping the langchain #108 (if unfixed), chromadb #84, and diskcache #41 rows.
- [X] T015 [US3] Shrink the `pip-audit --ignore-vuln` list in `.github/workflows/ci.yml` to only the kept-dismissed GHSAs; confirm the `dependency-audit` job passes (pip-audit + npm audit).

**Checkpoint**: records honest; suppression list minimal.

---

## Phase 6: Polish & Cross-Cutting Concerns

- [ ] T016 Confirm the upgraded set introduces **no new Dependabot alert of any severity** (FR-009 / clarification Q3); if any appears (on crewai 1.14 / rich 14 / openai 2 / langchain 1.x), upgrade it away rather than recording it.
- [ ] T017 Final acceptance: open critical/high alerts = 0 (SC-002), all SCs met; set spec 025 Status to Active in `specs/025-dependency-modernization/spec.md`; open the PR against `develop` referencing #332.

---

## Dependencies & Execution Order

- **Setup (T001)** → **Foundational (T002–T003)** → **US2 refactor (T004–T010)** → **US1 outcome (T011–T013)** → **US3 reconcile (T014–T015)** → **Polish (T016–T017)**.
- **Priority↔dependency inversion**: US1 is P1 (the outcome) but depends on US2 (P2, the enabler) — the lock can't pass gates until the adapters are migrated, so US2 executes first.
- **US3** depends on US1 (alerts must be fixed before their rows/ignores are removed).
- Within US2, `[P]` tasks touch different files: T005 ∥ T006 ∥ T007 ∥ T008 can run together; T004 (crewai) alongside them; T009 (test doubles) after the API changes settle; T010 (gate) last.

### Story dependency graph

```text
Setup → Foundational(re-lock) → US2(refactor) → US1(gates+alerts fixed) → US3(reconcile) → Polish
```

## Parallel Execution Examples

- **US2**: T004 ∥ T005 ∥ T006 ∥ T007 ∥ T008 (distinct files), then T009 (test doubles), then T010 (verify).
- **US3**: T014 ∥ T015 (different files; both after US1).

## Implementation Strategy

1. **Foundational first**: land the lock (Option-C versions) — everything else builds on it.
2. **MVP = Phases 2–4 (Foundational + US2 + US1)**: the upgraded tree is green and ~12 alerts are fixed — the substantive security win.
3. **US3**: reconcile the records so accepted-risk no longer covers fixed items.
4. **Polish**: zero-new-alerts confirmation + spec status + PR.

> **Residual (research R2)**: langchain caps at 1.3.2, so the langchain GHSA-gr75 alert (#108, unused file-search path) stays a not-reachable dismissal — it is intentionally NOT in the convert→fixed set.
