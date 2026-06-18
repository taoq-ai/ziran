# Tasks: Many-Shot Jailbreaking Vector Category

**Input**: Design documents from `/specs/023-many-shot-jailbreak/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: INCLUDED — Constitution III mandates unit + integration coverage ≥85%.

**Organization**: Tasks grouped by user story (US1 P1, US2 P2, US3 P3) so each is independently implementable and testable.

## Path Conventions

Single-project hexagonal layout: `ziran/` (library), `benchmarks/`, `tests/`, `docs/`.

---

## Phase 1: Setup

**Purpose**: Scaffolding only.

- [X] T001 [P] Add a "Long-context attacks" heading stub to `docs/concepts/attack-vectors.md` (filled with the many-shot description in polish)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: The many-shot mechanism (config model + renderer + synthetic corpus) every story builds on. **No user story can proceed until this is done.**

- [X] T002 Add `ManyShotConfig` (Pydantic, `n_shots: int = 50` with `ge=1, le=500`; `corpus: str`) and the optional `many_shot: ManyShotConfig | None = None` field on `AttackVector` in `ziran/domain/entities/attack.py` (per data-model.md)
- [X] T003 [P] Unit tests for the schema in `tests/unit/test_many_shot_config.py`: defaults (n_shots 50), out-of-range YAML value rejected by the `ge/le` bounds, `many_shot=None` by default, a vector with `many_shot` round-trips
- [X] T004 Author the synthetic shot corpus `ziran/application/attacks/many_shot_corpus.yaml`: harm-category-keyed ordered lists of synthetic `{q, a}` shots (non-operational placeholders — FR-004), covering the harm categories the vectors will use
- [X] T005 Implement `ShotRenderer` in `ziran/application/attacks/many_shot.py`: load the corpus once; `render(corpus_key, n)` deterministically assembles `n` shots by cycling the ordered list (stable formatting); `clamp(n) -> (value, warned)` enforcing [1, 500]; `estimate_tokens(text) -> len(text)//4`; unknown corpus key → clear error
- [X] T006 [P] Unit tests in `tests/unit/test_shot_renderer.py`: determinism (same key+n → identical text — SC-006), length scales with n (FR-006), clamp below 1 and above 500 with `warned=True` (SC-003), token estimate, unknown-key error
- [X] T007 [P] Corpus-safety unit test in `tests/unit/test_many_shot_corpus.py`: every corpus key has a non-empty ordered list; assert the corpus contains no banned operational markers (synthetic-only — FR-004). (The vector↔corpus key cross-check lives in US1/T010, after the vectors exist.)

**Checkpoint**: the config model, renderer, and safe corpus exist and are tested — US1 can begin.

---

## Phase 3: User Story 1 — Test agents against many-shot jailbreaking (Priority: P1) 🎯 MVP

**Goal**: ≥10 many-shot vectors that stack faux example exchanges before a final harmful request and run through the normal scan with correct taxonomy.

**Independent Test**: Load the library and confirm ≥10 many-shot vectors across harm categories with OWASP LLM01 + ATLAS T0054/T0065; run one through a scan and confirm the sent prompt stacks the shots before the final request and the detector evaluates the final request.

- [X] T008 [P] [US1] Author `ziran/application/attacks/vectors/many_shot_jailbreak.yaml`: ≥10 vectors across multiple harm categories, each using **valid enums** — `category: prompt_injection`, `target_phase: vulnerability_discovery` (NOT `jailbreak`/`exploitation`, which aren't enum members) — plus `tactic: single`, `many_shot: {n_shots: 50, corpus: <harm>}`, `owasp_mapping: [LLM01]`, `atlas_mapping: [AML.T0054, AML.T0065]`, `tags: [..., many-shot]`, `harm_category` set, with a synthetic final request (per contracts/vector-and-corpus-schema.md)
- [X] T009 [US1] Implement the many-shot prompt expansion in `ziran/application/agent_scanner/attack_executor.py`: for a vector carrying `many_shot`, build `prompt = ShotRenderer.render(corpus, effective_n) + "\n\n" + rendered_template` before `adapter.invoke`; the final request (rendered template) is unchanged so detectors evaluate it as usual (FR-008). (Effective-count resolution + clamp lands here; the scan-time override is wired in US2.)
- [X] T010 [P] [US1] Unit test in `tests/unit/test_many_shot_vectors.py`: the library loads ≥10 vectors with `many_shot`, each carrying OWASP LLM01 + ATLAS T0054 & T0065 + a `many-shot` tag, spanning ≥3 harm categories (SC-001); and every `many_shot.corpus` key referenced by a vector exists in the corpus (the vector↔corpus cross-check moved here from T007)
- [X] T011 [US1] Integration test in `tests/integration/test_many_shot_scan.py`: run a scan (MockAgentAdapter) against a many-shot vector and assert the prompt the adapter received stacks the configured shots followed by the final request, and the result is produced by the normal detection path (FR-002/FR-008), marked `@pytest.mark.integration`

**Checkpoint**: US1 closes the coverage gap — many-shot vectors exist and execute correctly. Shippable on its own at the default shot count.

---

## Phase 4: User Story 2 — Tune the shot count (Priority: P2)

**Goal**: Shot count is configurable via a scan-time override (on top of the per-vector YAML default) and the prompt scales accordingly.

**Independent Test**: Render/run a many-shot vector at a low and high shot count and confirm prompt length scales; a high count produces a long-context prompt; out-of-range values clamp.

- [X] T012 [US2] Thread the scan-time shot-count override + context budget through: `AgentScanner` reads `config["n_shots"]` and `config["context_window"]` (`ziran/application/agent_scanner/scanner.py`) and passes them to `AttackExecutor.__init__` (`ziran/application/agent_scanner/attack_executor.py`); the executor's effective-count = `clamp(override ?? vector.many_shot.n_shots)` (per data-model.md / R7)
- [X] T013 [P] [US2] Unit test in `tests/unit/test_many_shot_scaling.py`: `ShotRenderer.render(key, 100)` estimates ≥50,000 tokens and is longer than at 10 shots (SC-002); a scan-time override changes the effective shot count; an over-range override clamps with a warning (SC-003)
- [X] T014 [US2] Integration test in `tests/integration/test_many_shot_scan.py`: a scan-time `n_shots` override changes the number of stacked shots in the sent prompt (verifying the scanner→executor override path)

**Checkpoint**: shot count is tunable for susceptibility sweeps; the long-context exploit is real.

---

## Phase 5: User Story 3 — Safe long-context targeting + coverage visibility (Priority: P3)

**Goal**: Over-capacity prompts skip+warn (not error); the `many-shot` tag shows in the coverage report.

**Independent Test**: Run a many-shot vector with a small `context_window` and confirm it's skipped with a warning (prompt not sent); confirm the coverage report lists `many-shot`.

- [X] T015 [US3] Implement the context-capacity check in `ziran/application/agent_scanner/attack_executor.py`: when `estimate_tokens(prompt) > context_window`, skip the vector for that target and emit a warning with a clear reason (target context too small for N shots) — record a non-successful/skipped `AttackResult`, never error or silently drop (FR-007)
- [X] T016 [P] [US3] Integration test in `tests/integration/test_many_shot_scan.py`: with a small `context_window`, a many-shot vector is skipped and a warning recorded, and the adapter is NOT invoked with the oversized prompt (SC-004)
- [X] T017 [US3] Surface the coverage tag: expose the tag distribution (and/or a `many_shot_vectors` list) in `benchmarks/inventory.py`, and render a `many-shot` entry in `benchmarks/generate_all.py` → `coverage-comparison.md` (FR-009/SC-005)
- [X] T018 [P] [US3] Unit test in `tests/unit/test_inventory_many_shot.py`: `collect_inventory()` reports the `many-shot` tag count reflecting the new vectors

**Checkpoint**: incompatible targets are handled gracefully and the new coverage is discoverable.

---

## Phase 6: Polish & Cross-Cutting Concerns

- [X] T019 Fill the "Long-context attacks" section in `docs/concepts/attack-vectors.md`: explain many-shot jailbreaking, the `n_shots` config (default 50, max 500, scan-time override), the short-context skip/warn behaviour, and the synthetic-corpus safety boundary
- [X] T020 Run full quality gates: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`, `uv run pytest --cov=ziran` (≥85%) — fix any drift
- [X] T021 Walk the quickstart.md acceptance steps (SC-001…SC-006) end-to-end and confirm each passes; regenerate the coverage report and confirm the `many-shot` tag appears
- [X] T022 Set spec status to Active in `specs/023-many-shot-jailbreak/spec.md` and reference issue #276 in the PR

---

## Dependencies & Execution Order

- **Setup (Phase 1)** → **Foundational (Phase 2)** → **User Stories** → **Polish (Phase 6)**.
- **US1 (P1)** depends only on Foundational. MVP; ships alone at the default shot count.
- **US2 (P2)** depends on US1's executor hook (T009) + the renderer; adds the override path.
- **US3 (P3)** depends on US1's expansion (T009) for the capacity check, and on the vectors for the coverage tag.
- Within a story, `[P]` tasks touch different files and may run concurrently.

### Story dependency graph

```text
Setup → Foundational → US1 (MVP) ──┬─▶ US2 (tunable n_shots)
                                   └─▶ US3 (skip/warn + coverage)
```

## Parallel Execution Examples

- **Foundational**: T003 ∥ T006 ∥ T007 (tests) alongside the corpus/renderer; T002 first (schema).
- **US1**: T008 (vectors YAML) ∥ T010 (load test) alongside T009 (executor hook); T011 after T009.
- **US3**: T016 ∥ T018 alongside T015/T017.

## Implementation Strategy

1. **MVP = Phases 1–3 (US1)**: ≥10 many-shot vectors that stack shots and run with correct taxonomy — closes the coverage gap at the default shot count.
2. **Increment 2 = US2**: scan-time shot-count override + scaling (the long-context knob).
3. **Increment 3 = US3**: short-context skip/warn + `many-shot` coverage tag.
4. **Polish**: docs, gates, spec status.

> **Safety note**: T004 (corpus) and T007 (corpus-safety test) are load-bearing — the corpus MUST be synthetic/non-operational (FR-004). Author the corpus before the vectors and keep the safety test green.
