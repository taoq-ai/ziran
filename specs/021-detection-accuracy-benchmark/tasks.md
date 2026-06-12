# Tasks: Detector Accuracy Benchmark and Threshold Tuning

**Input**: Design documents from `/specs/021-detection-accuracy-benchmark/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: INCLUDED — Constitution III mandates unit + integration coverage ≥85%.

**Organization**: Tasks grouped by user story (US1 P1, US2 P2, US3 P3) so each is independently implementable and testable.

## Path Conventions

Single-project hexagonal layout: `ziran/` (library), `benchmarks/` (tooling), `tests/`, `docs/`.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Scaffolding only — no behaviour.

- [X] T001 Create dataset directory tree with `.gitkeep` files: `benchmarks/ground_truth/detection/{clear_refusal,partial_compliance,full_compliance,borderline}/`
- [X] T002 [P] Create methodology doc stub at `docs/reference/benchmarks/detection-accuracy.md` (headings: Overview, Dataset, Metrics, Threshold Tuning Methodology, Baseline, Re-recording judge verdicts)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Shared data models + offline-judge plumbing that US1 (and the dataset authoring it depends on) require. **No user story can proceed until this phase is done.**

- [X] T003 Add `ToolCallRecord`, `RecordedJudgeVerdict`, and `DetectionExample` Pydantic models to `benchmarks/ground_truth/schema.py`, reusing existing `ExpectedDetector`, `AttackConfig`, `SourceProvenance` (per data-model.md)
- [X] T004 [P] Unit tests for `DetectionExample` validation in `tests/unit/benchmarks/test_detection_schema.py`: rejects empty `response_text`, rejects unknown detector names, requires `recorded_judge` when `llm_judge` is in `expected_detectors`, enforces `example_id`/`category` prefix match
- [X] T005 Implement `ReplayLLMClient` in `benchmarks/replay_llm_client.py` implementing the `BaseLLMClient` port — returns the recorded judge verdict keyed by `example_id`, raises a clear error on an unknown id
- [X] T006 [P] Unit test for `ReplayLLMClient` in `tests/unit/benchmarks/test_replay_llm_client.py` (correct verdict returned; unknown id errors)

**Checkpoint**: schema + replay client exist and are tested — US1 can begin.

---

## Phase 3: User Story 1 — Published per-detector accuracy numbers (Priority: P1) 🎯 MVP

**Goal**: Run the real detector pipeline over the labelled dataset and emit precision/recall/F1 + confusion matrix per detector and for the pipeline.

**Independent Test**: `uv run python benchmarks/detection_accuracy.py` prints P/R/F1 + confusion matrix for refusal, indicator, side_effect, llm_judge and the pipeline, over ≥200 examples (≥50/category), and writes `benchmarks/results/detection_accuracy.json`.

### Dataset curation (the bulk of the effort)

- [~] T007 [P] [US1] (SEED: 3 done) Author ≥50 `clear_refusal` labelled examples in `benchmarks/ground_truth/detection/clear_refusal/*.yaml` (recorded response text/tool_calls/judge verdict, `expected_detectors`, overall `label`, provenance per contracts/dataset-schema.md)
- [~] T008 [P] [US1] (SEED: 3 done) Author ≥50 `full_compliance` labelled examples in `benchmarks/ground_truth/detection/full_compliance/*.yaml`
- [~] T009 [P] [US1] (SEED: 3 done) Author ≥50 `partial_compliance` labelled examples in `benchmarks/ground_truth/detection/partial_compliance/*.yaml`
- [~] T010 [P] [US1] (SEED: 3 done) Author ≥50 `borderline` labelled examples in `benchmarks/ground_truth/detection/borderline/*.yaml` (may be over-weighted — thresholds matter most here)
- [~] T011 [US1] (rubric done; floor pending full dataset) Write the labelling rubric section in `docs/reference/benchmarks/detection-accuracy.md` defining how each category is classified (FR-012), noting the dataset extends the spec-007 ground-truth fixtures and reuses its `ExpectedDetector`/provenance conventions (FR-004), then validate the whole dataset loads against `DetectionExample` and confirm ≥30 *applicable* examples exist for each of the four in-scope detectors (FR-003); add examples to fill any detector below the floor

### Metrics + harness

- [X] T012 [P] [US1] Add `ConfusionMatrix`, `DetectorMetrics`, `DetectorAccuracyResult` Pydantic models to `benchmarks/detection_accuracy.py` (per data-model.md)
- [X] T013 [US1] Implement metric computation in `benchmarks/detection_accuracy.py`: per-detector confusion matrix vs `expected_detectors.should_fire` (excluding not-applicable), pipeline confusion matrix vs overall `label`, precision/recall/F1, reusing `_wilson_ci` from `benchmarks/accuracy_metrics.py` for F1 CIs
- [X] T014 [US1] Implement dataset loader + runner in `benchmarks/detection_accuracy.py`: load `DetectionExample`s, build `DetectorPipeline(llm_client=ReplayLLMClient(...))`, run `evaluate()` per example via `asyncio.run`, aggregate into `DetectorAccuracyResult`
- [X] T015 [US1] Add the coverage check (fail if any category < 50 examples OR any in-scope detector has < 30 applicable examples — FR-003) and dataset-validation error handling (clear message naming the offending file) to `benchmarks/detection_accuracy.py`; report per-detector applicable counts
- [X] T016 [US1] Implement the Click CLI for `benchmarks/detection_accuracy.py` (`--json`, `--dataset`, `--by-category`, `--format`; `--config` wired in US2) writing JSON to `benchmarks/results/detection_accuracy.json` and printing table/markdown
- [X] T017 [US1] Add the detection-accuracy row to `docs/reference/benchmarks/coverage-comparison.md` (FR-005)

### Tests + published numbers

- [X] T018 [P] [US1] Unit tests for metric math in `tests/unit/benchmarks/test_detection_metrics.py`: known confusion matrices → expected P/R/F1; not-applicable detectors excluded; class-imbalance case
- [X] T019 [US1] Integration test in `tests/integration/test_detection_accuracy_harness.py`: run the harness over a small fixture dataset slice through the real pipeline, assert deterministic per-detector + pipeline metrics (SC-006), marked `@pytest.mark.integration`
- [ ] T020 [US1] Run the harness over the full dataset and record the baseline numbers into the "Baseline" section of `docs/reference/benchmarks/detection-accuracy.md` (SC-001)

**Checkpoint**: US1 delivers published, reproducible per-detector accuracy — the MVP, shippable on its own.

---

## Phase 4: User Story 2 — Operator-tunable thresholds (Priority: P2)

**Goal**: Detector thresholds configurable via `.ziran/detectors.yaml`; shipped defaults reproduce current behaviour exactly.

**Independent Test**: Edit a threshold in `.ziran/detectors.yaml`, re-run a detection → verdict changes; delete the file → documented defaults apply unchanged.

- [X] T021 [US2] Create `DetectorThresholds` Pydantic model in `ziran/application/detectors/thresholds.py` with defaults matching today's constants (hit 0.7, safe 0.3, side_effect_confidence 0.8, refusal/indicator_confidence 0.5, side_effect_min_confidence 0.7), range validators, and a `hit > safe` cross-field validator (FR-008)
- [X] T022 [P] [US2] Unit tests in `tests/unit/detectors/test_thresholds.py`: defaults equal current constants; out-of-range value errors naming field+value; `hit <= safe` errors
- [X] T023 [US2] Implement config loader in `ziran/infrastructure/config/detectors.py` using existing `load_yaml_with_env` — load `.ziran/detectors.yaml` → `DetectorThresholds`; absent file → defaults; invalid → clear error (FR-006/FR-008)
- [X] T024 [P] [US2] Unit tests in `tests/unit/infrastructure/test_detectors_config.py`: absent file → defaults; partial file → merged with defaults; malformed/out-of-range → error; `!env`/`${VAR}` interpolation works
- [X] T025 [US2] Thread thresholds through the pipeline: add `thresholds` field to `DetectorConfig` and `DetectorPipeline.__init__`, then replace EVERY pipeline-level magic number with an instance value. First `grep -n` `pipeline.py` for all numeric literals in `_HIT_THRESHOLD`/`_SAFE_THRESHOLD` and the confidence gates (~lines 263–339, incl. the authorization branch); enumerate each literal and confirm it maps to a `DetectorThresholds` field — if any literal has no field, add a field for it rather than leaving it hardcoded
- [X] T026 [US2] Regression test in `tests/unit/detectors/test_pipeline_thresholds.py`: pipeline with default `DetectorThresholds()` produces byte-for-byte identical verdicts to pre-change behaviour, with inputs that exercise EVERY gate (refusal-wins, side-effect-override, indicator-hit, authorization, llm_judge hit/safe paths) — not just representative ones (FR-007); and a lowered `hit` flips a borderline verdict (SC-003)
- [ ] T027 [US2] Wire `--config` into `benchmarks/detection_accuracy.py` so the harness applies operator thresholds
- [ ] T028 [US2] Write the "Threshold Tuning Methodology" section in `docs/reference/benchmarks/detection-accuracy.md`: rationale for each default value and revisit conditions (FR-011, SC-005)

**Checkpoint**: thresholds are config-driven; defaults preserve behaviour; methodology documented.

---

## Phase 5: User Story 3 — Regression protection on detector changes (Priority: P3)

**Goal**: CI gate fails when pipeline F1 drops > 0.02 below the recorded baseline; allows explicit baseline update.

**Independent Test**: Degrade a detector on a branch → `detection_regression.py` exits non-zero; revert → exits zero.

- [X] T029 [US3] Add `DetectionAccuracyBaseline` Pydantic model and implement `benchmarks/detection_regression.py` (Click CLI) comparing current pipeline F1 vs baseline with 0.02 tolerance; `--update-baseline`, `--baseline`, `--format`; exit codes 0/1/2 per contracts/cli.md
- [X] T030 [US3] Generate and commit the initial *regression baseline* `benchmarks/results/detection_accuracy_baseline.json` via `--update-baseline` (this is the machine-readable gate baseline, distinct from the human-readable *published baseline* recorded in docs by T020 — FR-009)
- [X] T031 [P] [US3] Unit/integration tests in `tests/integration/test_detection_regression.py`: pass when F1 ≥ baseline−0.02; fail (exit 1) on a deliberate F1 drop; exit 2 when baseline missing; per-detector deltas never block (Q3)
- [X] T032 [US3] Add a CI job in `.github/workflows/` that runs the regression gate. To stay compatible with branch protection, the job MUST **always run** (no `paths:` trigger filter) but **skip the gate logic and report success** when the diff does not touch `ziran/application/detectors/**`, the dataset, or threshold files (detect changed paths inside the job, e.g. via `git diff --name-only` or a changed-files step). This avoids the required-check deadlock where a path-filtered required check never reports on unrelated PRs. The gate runs `detection_regression.py` and is blocking on `main`
- [X] T033 [US3] Document the gate (metric, tolerance, how to update the baseline) in `docs/reference/benchmarks/detection-accuracy.md`

**Checkpoint**: accuracy regressions are automatically blocked; baseline updates are explicit and reviewed.

---

## Phase 6: Polish & Cross-Cutting Concerns

- [ ] T034 [P] Update detection-accuracy claims in `README.md` (and any benchmark dashboard copy) to cite the published baseline numbers instead of unvalidated assumptions
- [ ] T035 Run full quality gates: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`, `uv run pytest --cov=ziran` (≥85%) — fix any drift
- [ ] T036 Walk the quickstart.md acceptance steps (SC-001…SC-006) end-to-end and confirm each passes
- [ ] T037 Set spec status to Active in `specs/021-detection-accuracy-benchmark/spec.md` and reference issue #279 in the PR

---

## Dependencies & Execution Order

- **Setup (Phase 1)** → **Foundational (Phase 2)** → **User Stories** → **Polish (Phase 6)**.
- **US1 (P1)** depends only on Foundational. It is the MVP and can ship alone.
- **US2 (P2)** is independent of US1's harness except T027 (wiring `--config` into the harness), which needs T016. US2's library work (T021–T026) can proceed in parallel with US1.
- **US3 (P3)** depends on US1 (needs the harness + a `DetectorAccuracyResult`/F1 to baseline against): T029–T030 require T013–T016.
- Within a story, `[P]` tasks touch different files and may run concurrently.

### Story dependency graph

```text
Setup → Foundational → US1 (MVP) ─────────────▶ US3 (gate)
                         │
                         └── US2 (thresholds, mostly parallel; T027 joins US1)
```

## Parallel Execution Examples

- **Foundational**: T004 ∥ T006 (after T003/T005 respectively).
- **US1 dataset**: T007 ∥ T008 ∥ T009 ∥ T010 (four separate category dirs), then T011.
- **US1 metrics**: T012 ∥ T018 alongside the dataset work; T013–T016 sequential (same file).
- **US2**: T021→T022, T023→T024, then T025→T026 — the model/loader pairs are parallel to each other.

## Implementation Strategy

1. **MVP = Phases 1–3 (US1)**: published, reproducible per-detector accuracy. Shippable and unblocks every downstream accuracy claim.
2. **Increment 2 = US2**: operator tunability + documented, benchmark-justified defaults.
3. **Increment 3 = US3**: lock it in with the CI regression gate.
4. **Polish**: update external claims, run gates, flip spec status.

> **Effort note**: T007–T010 (≥200 labelled examples with recorded responses) are curation-heavy, not code-heavy — budget accordingly; the rest of US1 is small and well-anchored to existing patterns.
