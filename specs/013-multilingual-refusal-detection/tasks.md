# Tasks: Multilingual Refusal Detection

**Input**: Design documents from `/specs/013-multilingual-refusal-detection/`
**Prerequisites**: plan.md (required), spec.md (required), research.md, data-model.md

**Tests**: Included — the constitution requires unit tests for all business logic.

**Organization**: Tasks grouped by user story for independent implementation and testing.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

---

## Phase 1: Setup

**Purpose**: No project initialization needed — this feature extends existing modules. Phase is empty.

---

## Phase 2: Foundational (Language Pattern Tuples)

**Purpose**: Add multilingual refusal pattern tuples that all user stories depend on.

**CRITICAL**: No user story work can begin until these patterns exist.

- [ ] T001 [P] Add Spanish refusal pattern tuples (REFUSAL_PREFIXES_ES, REFUSAL_SUBSTRINGS_ES) with 10-15 curated phrases in `ziran/application/detectors/refusal.py`
- [ ] T002 [P] Add French refusal pattern tuples (REFUSAL_PREFIXES_FR, REFUSAL_SUBSTRINGS_FR) with 10-15 curated phrases in `ziran/application/detectors/refusal.py`
- [ ] T003 [P] Add German refusal pattern tuples (REFUSAL_PREFIXES_DE, REFUSAL_SUBSTRINGS_DE) with 10-15 curated phrases in `ziran/application/detectors/refusal.py`
- [ ] T004 [P] Add Portuguese refusal pattern tuples (REFUSAL_PREFIXES_PT, REFUSAL_SUBSTRINGS_PT) with 10-15 curated phrases in `ziran/application/detectors/refusal.py`
- [ ] T005 [P] Add Chinese refusal pattern tuples (REFUSAL_PREFIXES_ZH, REFUSAL_SUBSTRINGS_ZH) with 10-15 curated phrases in `ziran/application/detectors/refusal.py`
- [ ] T006 [P] Add Japanese refusal pattern tuples (REFUSAL_PREFIXES_JA, REFUSAL_SUBSTRINGS_JA) with 10-15 curated phrases in `ziran/application/detectors/refusal.py`
- [ ] T007 Add LANGUAGE_PATTERNS registry dict mapping ISO 639-1 codes to their pattern tuples in `ziran/application/detectors/refusal.py`

**Checkpoint**: All 6 language pattern tuples and registry exist. Patterns are curated from real LLM refusal outputs.

---

## Phase 3: User Story 1 - Detect refusals in non-English responses (Priority: P1) MVP

**Goal**: RefusalDetector accepts a `languages` parameter and detects refusals in all configured languages.

**Independent Test**: Instantiate `RefusalDetector(languages=["all"])`, pass a Spanish refusal → score 0.0.

### Tests for User Story 1

- [ ] T008 [P] [US1] Add test class TestRefusalDetectorSpanish with 10+ Spanish refusal phrases in `tests/unit/test_refusal_multilingual.py`
- [ ] T009 [P] [US1] Add test class TestRefusalDetectorFrench with 10+ French refusal phrases in `tests/unit/test_refusal_multilingual.py`
- [ ] T010 [P] [US1] Add test class TestRefusalDetectorGerman with 10+ German refusal phrases in `tests/unit/test_refusal_multilingual.py`
- [ ] T011 [P] [US1] Add test class TestRefusalDetectorPortuguese with 10+ Portuguese refusal phrases in `tests/unit/test_refusal_multilingual.py`
- [ ] T012 [P] [US1] Add test class TestRefusalDetectorChinese with 10+ Chinese refusal phrases in `tests/unit/test_refusal_multilingual.py`
- [ ] T013 [P] [US1] Add test class TestRefusalDetectorJapanese with 10+ Japanese refusal phrases in `tests/unit/test_refusal_multilingual.py`
- [ ] T014 [P] [US1] Add test class TestRefusalDetectorAll verifying `languages=["all"]` detects all languages in `tests/unit/test_refusal_multilingual.py`

### Implementation for User Story 1

- [ ] T015 [US1] Modify `RefusalDetector.__init__()` to accept `languages: Sequence[str] | None = None` parameter and rebuild mega-regex from selected language patterns in `ziran/application/detectors/refusal.py`
- [ ] T016 [US1] Add warning logging for unknown language codes in `RefusalDetector.__init__()` in `ziran/application/detectors/refusal.py`

**Checkpoint**: `RefusalDetector(languages=["all"])` detects refusals in all 7 languages. All per-language tests pass.

---

## Phase 4: User Story 2 - Backward-compatible English-only default (Priority: P1)

**Goal**: Default behavior (no `languages` parameter) is identical to pre-change behavior.

**Independent Test**: Instantiate `RefusalDetector()` with no args, verify English detection works and non-English does not match.

### Tests for User Story 2

- [ ] T017 [P] [US2] Add test class TestRefusalDetectorDefaults verifying `languages=None` matches English and rejects non-English in `tests/unit/test_refusal_multilingual.py`
- [ ] T018 [P] [US2] Add test class TestRefusalDetectorUnknownLanguage verifying unknown codes log warning and don't crash in `tests/unit/test_refusal_multilingual.py`

### Implementation for User Story 2

- [ ] T019 [US2] Verify all existing tests in `tests/unit/test_detectors.py` pass without modification (no code change — validation only)

**Checkpoint**: Existing test suite passes unchanged. Default RefusalDetector behavior is identical to pre-change.

---

## Phase 5: User Story 3 - Opt-in language selection (Priority: P2)

**Goal**: Users can configure specific languages via `languages=["es", "fr"]`.

**Independent Test**: `RefusalDetector(languages=["es", "fr"])` detects Spanish/French but not Japanese.

### Tests for User Story 3

- [ ] T020 [P] [US3] Add test class TestRefusalDetectorSelectiveLanguages verifying subset selection works in `tests/unit/test_refusal_multilingual.py`
- [ ] T021 [P] [US3] Add test class TestRefusalDetectorMixedLanguageResponse verifying refusal detection in mixed-language text in `tests/unit/test_refusal_multilingual.py`
- [ ] T022 [P] [US3] Add test class TestRefusalDetectorMatchTypes verifying all 3 match types work with multilingual patterns in `tests/unit/test_refusal_multilingual.py`

### Implementation for User Story 3

No additional implementation needed — the `languages` parameter logic from US1 (T015) already handles selective language configuration. This phase is tests-only to validate the behavior.

**Checkpoint**: Selective language configuration works. All match types work with multilingual patterns.

---

## Phase 6: User Story 4 - Pipeline integration (Priority: P2)

**Goal**: Language config flows from `DetectorConfig` through `DetectorPipeline` to `RefusalDetector`.

**Independent Test**: Create `DetectorPipeline(detector_config=DetectorConfig(refusal_languages=["es"]))` and verify the refusal detector uses Spanish patterns.

### Tests for User Story 4

- [ ] T023 [P] [US4] Add test class TestDetectorPipelineMultilingual verifying pipeline passes languages to RefusalDetector in `tests/unit/test_refusal_multilingual.py`

### Implementation for User Story 4

- [ ] T024 [US4] Add `refusal_languages: Sequence[str] | None = None` field to `DetectorConfig` dataclass in `ziran/application/detectors/pipeline.py`
- [ ] T025 [US4] Pass `languages=config.refusal_languages` to `RefusalDetector()` constructor in `DetectorPipeline.__init__()` in `ziran/application/detectors/pipeline.py`

**Checkpoint**: Pipeline integration complete. End-to-end multilingual detection works through the pipeline.

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Quality gates and cleanup.

- [ ] T026 Run `uv run ruff check .` and fix any lint violations
- [ ] T027 Run `uv run ruff format --check .` and fix any formatting drift
- [ ] T028 Run `uv run mypy ziran/` and fix any type errors
- [ ] T029 Run `uv run pytest --cov=ziran` and verify coverage >= 85%
- [ ] T030 Run full existing test suite and verify zero regressions

---

## Dependencies & Execution Order

### Phase Dependencies

- **Foundational (Phase 2)**: No dependencies — can start immediately
- **US1 (Phase 3)**: Depends on Phase 2 (pattern tuples must exist)
- **US2 (Phase 4)**: Depends on Phase 3 (needs `languages` parameter implemented)
- **US3 (Phase 5)**: Depends on Phase 3 (needs `languages` parameter implemented)
- **US4 (Phase 6)**: Depends on Phase 3 (needs RefusalDetector changes)
- **Polish (Phase 7)**: Depends on all phases complete

### User Story Dependencies

- **US1 (P1)**: Blocked by Phase 2 only
- **US2 (P1)**: Blocked by US1 (validates default behavior of `languages` param)
- **US3 (P2)**: Blocked by US1 (tests subset selection of `languages` param)
- **US4 (P2)**: Blocked by US1 (needs RefusalDetector `languages` param to exist)

### Within Each User Story

- Tests written first, verified to fail
- Implementation follows
- Tests verified to pass

### Parallel Opportunities

- T001-T006: All 6 language tuple tasks can run in parallel
- T008-T014: All per-language test classes can run in parallel
- T017-T018, T020-T022, T023: Test tasks within each story can run in parallel
- US3 and US4 can run in parallel after US1 completes

---

## Parallel Example: Phase 2

```bash
# Launch all language pattern tasks together:
Task: "Add Spanish refusal patterns in ziran/application/detectors/refusal.py"
Task: "Add French refusal patterns in ziran/application/detectors/refusal.py"
Task: "Add German refusal patterns in ziran/application/detectors/refusal.py"
Task: "Add Portuguese refusal patterns in ziran/application/detectors/refusal.py"
Task: "Add Chinese refusal patterns in ziran/application/detectors/refusal.py"
Task: "Add Japanese refusal patterns in ziran/application/detectors/refusal.py"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 2: Add all language patterns
2. Complete Phase 3: US1 — core multilingual detection
3. **STOP and VALIDATE**: Test `RefusalDetector(languages=["all"])` independently
4. This alone delivers the primary value

### Incremental Delivery

1. Phase 2 → Foundation ready (patterns exist)
2. US1 → Core detection works → MVP
3. US2 → Backward compatibility validated
4. US3 + US4 (parallel) → Selective languages + pipeline integration
5. Phase 7 → Quality gates pass

---

## Notes

- All language patterns are in a single file (`refusal.py`) — parallel tasks T001-T006 touch the same file, so in practice they should be done sequentially or carefully merged
- English is always included regardless of `languages` parameter (see research.md R4)
- CJK patterns (Chinese, Japanese) work with Python `re` module without special handling (see research.md R2)
- Total task count: 30
- Tasks per user story: US1=9, US2=3, US3=3, US4=3
