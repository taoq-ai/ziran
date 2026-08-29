# Tasks: Eliminate indicator-matching false positives in the detection pipeline

**Input**: Design documents from `/specs/027-detector-indicator-false-positives/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, quickstart.md

**Tests**: Included — the spec (FR-006) explicitly requires regression + positive tests (TDD).

**Branch**: `fix/027-detector-indicator-false-positives` (off `develop`)

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: US1 / US2 / US3 from spec.md

## Path Conventions

Single-project hexagonal layout: source in `ziran/`, tests in `tests/`, attack data in `ziran/application/attacks/vectors/`, benchmark data in `benchmarks/`.

---

## Phase 1: Setup

- [ ] T001 Confirm branch `fix/027-detector-indicator-false-positives` is checked out off latest `develop`; export `SPECIFY_FEATURE=027-detector-indicator-false-positives`.
- [ ] T002 Build the generic-indicator inventory: run a triage script over `ziran/application/attacks/vectors/*.yaml` to list every bare topical single-word `success_indicators` value with its vector id and category; save the list as a working note for Phase 5 curation.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Detector-level changes that every user story depends on.

- [ ] T003 [US1] Add `_CAPABILITY_CONTEXT_PHRASES: tuple[str, ...]` and `_is_capability_context(text: str) -> bool` to `ziran/application/detectors/indicator.py`, mirroring `_DESCRIPTIVE_CONTEXT_PHRASES` / `_is_descriptive_context` (phrase set per research.md Decision 1).
- [ ] T004 [US1] Wire the capability guard into `_is_genuine_match` in `ziran/application/detectors/indicator.py`: for each non-negated occurrence, compute a window (±120 chars, matching the echo window) and skip the occurrence when `_is_capability_context(window)` is true; apply to ALL occurrences (not only prompt-echoed ones). Keep negation + descriptive-echo guards intact.
- [ ] T005 [US3] Change `DetectorConfig.indicator_matchtype` default from `"str"` to `"word"` in `ziran/application/detectors/pipeline.py`.

**Checkpoint**: Detector now ignores self-description hits and matches whole words by default.

---

## Phase 3: User Story 1 - Benign capability descriptions are not flagged (P1) 🎯 MVP

**Goal**: The reported Quanta self-description produces no finding.

**Independent Test**: Replay the exact prompt + Quanta response through the pipeline → `successful = false`, no genuine matched indicators.

- [ ] T006 [US1] Add a unit test in `tests/unit/test_detectors.py` reproducing the FP: prompt = "...sample record from the user database", response = the Quanta self-description; assert `verdict.successful is False` and no spurious genuine indicators. (Write first; must fail before T003–T004, pass after.)
- [ ] T007 [P] [US1] Add focused unit tests for `_is_capability_context` in `tests/unit/test_detectors.py`: positive (self-description windows) and negative (genuine disclosure window) cases.
- [ ] T008 [US1] Add a should-NOT-flag scenario to `tests/integration/test_detection_regression.py` for the Quanta capability-description exchange.

**Checkpoint**: US1 independently verifiable and green.

---

## Phase 4: User Story 2 - Genuine disclosures are still caught (P1)

**Goal**: Recall preserved — real disclosures still flag.

**Independent Test**: Replay a genuine-disclosure response → `successful = true`.

- [ ] T009 [US2] Add a positive unit test in `tests/unit/test_detectors.py`: data-access probe + response containing an actual record (e.g. `email: alice@corp.com, phone: 555-0100`); assert `verdict.successful is True`. (Guards against over-suppression.)
- [ ] T010 [US2] Add benign capability-description case(s) (Quanta-style) as labelled negatives to the detection dataset under `benchmarks/ground_truth/detection/`.
- [ ] T011 [US2] Run the detection-accuracy benchmark (spec-021 entry point); confirm precision improves and recall does not regress vs the recorded baseline. Update the baseline artifact only if the change is intentional and reviewed.

**Checkpoint**: Precision up, recall unchanged — verified by benchmark.

---

## Phase 5: User Story 3 - Topical words inside compound tokens do not match (P2)

**Goal**: `email` ∌ `send_email_report`; `data` ∌ `database`.

**Independent Test**: Unit tests asserting word-boundary behavior.

- [ ] T012 [P] [US3] Add unit tests in `tests/unit/test_detectors.py` proving `send_email_report` does not match `email` and `search_database` does not match `data`, while a standalone token in a disclosure still matches.
- [ ] T013 [US3] Curate generic indicators across ALL vectors in `ziran/application/attacks/vectors/*.yaml` using the T002 inventory: replace bare topical single-word `success_indicators` that name the attack's subject with evidence-bearing indicators (concrete value markers, `field:` labels, multi-token phrases, or 2+ corroborating indicators). Preserve each attack's intent; start with `multi_turn_tactics.yaml`, `authorization.yaml`, `a2a_attacks.yaml`, `data_exfiltration.yaml`.
- [ ] T014 [US3] Run the vector loader/schema tests (e.g. `uv run pytest -k vector`) to confirm all curated YAMLs still parse and validate.

**Checkpoint**: Mechanical substring/topical class removed at matcher + data level.

---

## Phase 6: Polish & Quality Gates

- [ ] T015 Re-run the detection-accuracy benchmark after curation (T013) to confirm no recall regression introduced by the YAML changes.
- [ ] T016 Run all quality gates: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`, `uv run pytest --cov=ziran` (coverage ≥ 85%). Fix any failures.
- [ ] T017 Update the spec status to Active; ensure `specs/027-.../` artifacts are consistent.
- [ ] T018 Open a PR against `develop` titled `fix(detectors): eliminate indicator-matching false positives` linking issue #350, with labels (`bug`, `python`, `complexity: medium`, `priority: high`); after push, check `gh pr checks` and fix any CI failures.

---

## Dependencies & Execution Order

- **Setup (T001–T002)** → **Foundational (T003–T005)** → user stories.
- **US1 (T006–T008)** depends on T003–T004. T006 (failing test) authored before T003–T004 per TDD.
- **US2 (T009–T011)** depends on the detector changes; T011 depends on T010.
- **US3 (T012)** depends on T005; **T013 curation** depends on T002 inventory and benefits from T005; **T014** depends on T013.
- **Polish (T015–T018)** last; T015 depends on T013.

## Parallel Opportunities

- T007 and T012 are independent unit-test additions (different test cases, same file — coordinate to avoid edit conflicts; otherwise sequential).
- Vector curation (T013) can be split per-file across the four high-risk files in parallel, then the remaining vectors.

## MVP Scope

US1 (T001–T008) alone fixes the reported false positive and is the minimum shippable increment. US2 + US3 complete the systemic fix and recall guarantee.
