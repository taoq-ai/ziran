---
description: "Tasks for Benchmark Maturity release (012)"
---

# Tasks: Benchmark Maturity

**Input**: Design documents from `/specs/012-benchmark-maturity/`
**Prerequisites**: plan.md, spec.md (user stories), research.md, data-model.md, contracts/, quickstart.md

**Tests**: Coverage ≥ 85% is a constitution requirement, so test tasks are included alongside implementation. No strict TDD ordering enforced — write tests in the same PR as the implementation they cover.

**Organization**: Tasks are grouped by user story (US1–US5, matching spec.md priorities). Cross-cutting ATLAS CLI and report-surface work lives within US1 because it is the user-visible delivery of the ATLAS mapping. Release polish lives in the final phase.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no in-flight dependency)
- **[Story]**: Which user story a task belongs to (US1, US2, US3, US4, US5)
- All paths are relative to repo root

## Path Conventions (project-specific)

- Domain: `ziran/domain/entities/`
- Application: `ziran/application/`
- Interfaces (CLI): `ziran/interfaces/cli/`
- Infrastructure: `ziran/infrastructure/`
- Attack vectors (YAML): `ziran/application/attacks/vectors/`
- Benchmark tooling: `benchmarks/`
- Docs: `docs/reference/benchmarks/`
- Tests: `tests/unit/`, `tests/integration/`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Baseline validation before any changes land on the feature branch.

- [X] T001 Verify branch `012-benchmark-maturity` is checked out and baseline quality gates pass (`uv run ruff check . && uv run ruff format --check . && uv run mypy ziran/ && uv run pytest -q`)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Domain enums, mapping fields, and library helpers that every user story touching ATLAS (US1, US2, US3, US4) depends on. US5 (defence profile) is independent and does its own foundational work inside its phase.

**⚠️ CRITICAL**: No user-story work on ATLAS may begin until this phase is complete.

### Domain: ATLAS taxonomy

- [X] T002 Add `AtlasTactic` StrEnum (15 values from October 2025 ATLAS snapshot) to `ziran/domain/entities/attack.py`
- [X] T003 Add `AtlasTechnique` StrEnum seeded with the 14 agent-specific techniques plus the ~20 techniques that cover the existing top-category vectors (prompt injection, tool manipulation, exfiltration) in `ziran/domain/entities/attack.py`
- [X] T004 Add `ATLAS_TECHNIQUE_DESCRIPTIONS: dict[AtlasTechnique, str]` to `ziran/domain/entities/attack.py` (must be complete for every enum member)
- [X] T005 Add `ATLAS_TECHNIQUE_TO_TACTIC: dict[AtlasTechnique, AtlasTactic]` to `ziran/domain/entities/attack.py` (must be complete for every enum member)
- [X] T006 Add `AGENT_SPECIFIC_TECHNIQUES: frozenset[AtlasTechnique]` with exactly the 14 agent-specific techniques to `ziran/domain/entities/attack.py`

### Domain: mapping fields on existing entities

- [X] T007 [P] Add `atlas_mapping: list[AtlasTechnique] = Field(default_factory=list, ...)` to `AttackVector` in `ziran/domain/entities/attack.py`
- [X] T008 [P] Add `atlas_mapping: list[AtlasTechnique] = Field(default_factory=list, ...)` to `AttackResult` in `ziran/domain/entities/attack.py` and propagate from vector to result in the scanner dispatch path (mirror how `owasp_mapping` is copied today — search `owasp_mapping=` in `ziran/application/` to locate call sites)

### Application: library helpers

- [X] T009 Add `AttackLibrary.get_attacks_by_atlas(technique: AtlasTechnique) -> list[AttackVector]` in `ziran/application/attacks/library.py` (mirror `get_attacks_by_owasp` exactly)
- [X] T010 Add `AttackLibrary.lint_atlas_coverage() -> list[str]` in `ziran/application/attacks/library.py` — returns vector IDs whose `atlas_mapping` is empty

### Tests (foundational)

- [X] T011 [P] Unit test `tests/unit/test_atlas_enum.py` implementing the 7 contract tests from `contracts/atlas-taxonomy.md` (enum completeness ×2, agent-specific cardinality, subset property, tactic-reference validity, technique ID regex, tactic ID regex)
- [X] T012 [P] Unit test `tests/unit/test_library_atlas_filter.py` covering `get_attacks_by_atlas` (valid technique, unknown technique, empty-library case) and `lint_atlas_coverage` (reports vectors with empty mapping, returns empty when all mapped)
- [X] T013 [P] Unit test `tests/unit/test_attack_vector_atlas_field.py` confirming `AttackVector` and `AttackResult` round-trip `atlas_mapping` through `model_dump`/`model_validate` and that the field defaults to empty list for YAML without it

**Checkpoint**: Foundation ready. ATLAS enum exists, mapping field on vectors/results is live (empty defaults), library filters and lint helper usable. US1–US4 can begin.

---

## Phase 3: User Story 1 — Align ZIRAN findings with MITRE ATLAS (Priority: P1) 🎯 MVP

**Goal**: Every attack vector carries an ATLAS technique mapping. The benchmark dashboard reports ATLAS coverage. Reports and the CLI library listing surface ATLAS IDs alongside OWASP. This is the flagship deliverable of the release and the "ATLAS mapping" row on the coverage comparison moves from 0 to ≥ 60 techniques.

**Independent Test**: Run `uv run python benchmarks/atlas_coverage.py` — every vector is mapped, ≥ 60 techniques covered, all 14 agent-specific techniques present. Run `ziran library --atlas AML.T0051` — returns a non-empty list. View any campaign report — every finding shows an ATLAS technique.

### ATLAS enum expansion to cover existing library (iterative — grows with annotation)

- [X] T014 [US1] Enumerate every MITRE ATLAS technique that will be referenced during annotation, expanding `AtlasTechnique`, `ATLAS_TECHNIQUE_DESCRIPTIONS`, and `ATLAS_TECHNIQUE_TO_TACTIC` until the enum covers ≥ 60 techniques. Source the IDs and names from the October 2025 ATLAS release notes and matrix

### Retro-mapping pass — annotate `atlas_mapping` on every existing vector

Each task below touches one file (or a tight family of closely-related files) and can run in parallel with the others.

- [X] T015 [P] [US1] Annotate `ziran/application/attacks/vectors/prompt_injection.yaml` — every vector gets one or more ATLAS technique IDs
- [X] T016 [P] [US1] Annotate prompt-injection family in `ziran/application/attacks/vectors/jailbreakbench.yaml`, `multi_turn_tactics.yaml`, and `expanded_tactics.yaml`
- [X] T017 [P] [US1] Annotate `ziran/application/attacks/vectors/chain_of_thought_manipulation.yaml` and `memory_poisoning.yaml`
- [X] T018 [P] [US1] Annotate indirect-injection family: `ziran/application/attacks/vectors/indirect_injection.yaml`, `indirect_injection_escalation.yaml`, `indirect_injection_exfiltration.yaml`, `indirect_injection_tool_abuse.yaml`
- [X] T019 [P] [US1] Annotate `ziran/application/attacks/vectors/mcp_attacks.yaml`, `mcp_attacks_expanded.yaml`, and `model_dos.yaml`
- [X] T020 [P] [US1] Annotate `ziran/application/attacks/vectors/data_exfiltration.yaml` and `system_prompt_extraction.yaml`
- [X] T021 [P] [US1] Annotate `ziran/application/attacks/vectors/authorization.yaml` and `privilege_escalation.yaml`
- [X] T022 [P] [US1] Annotate `ziran/application/attacks/vectors/multi_agent.yaml`, `a2a_attacks.yaml`, and `rjudge.yaml`
- [X] T023 [P] [US1] Annotate `ziran/application/attacks/vectors/harmful_tasks.yaml`, `harmful_tasks_expanded.yaml`, and `alert_coverage.yaml`

### Benchmark script and dashboard

- [X] T024 [US1] Create `benchmarks/atlas_coverage.py` implementing the JSON schema and stdout table defined in `contracts/benchmark-reports.md` (uses `ATLAS_TECHNIQUE_TO_TACTIC` and `AGENT_SPECIFIC_TECHNIQUES`; exit code 0 on full coverage, 1 on empty mappings or missing agent-specific techniques)
- [X] T025 [US1] Add `benchmarks/atlas_coverage.py` to the regeneration list in `benchmarks/generate_all.py`
- [X] T026 [US1] Extend `benchmarks/benchmark_comparison.py` with a MITRE ATLAS row whose numerator is the count of covered techniques (from `atlas_coverage.py`) and denominator is `len(AtlasTechnique)`

### CLI and report surface

- [X] T027 [US1] Add `--atlas` option to the `library` subcommand in `ziran/interfaces/cli/main.py` (Click choice derived from `AtlasTechnique`; include `difflib.get_close_matches` suggestion on invalid values; compose with existing `--owasp`, `--category`, `--severity`, `--tag` as AND)
- [X] T028 [US1] Add an `ATLAS` column to the `library` subcommand's Rich table output in `ziran/interfaces/cli/main.py` (mirror the existing `OWASP` column rendering)
- [X] T029 [US1] Add an "ATLAS" section to the Markdown report template in `ziran/interfaces/cli/reports.py` — per-finding technique list and a tactic-level coverage summary, with agent-specific techniques highlighted
- [X] T030 [US1] Add the equivalent "ATLAS" section to the HTML report template (same file or adjacent — whichever holds the current OWASP compliance table)
- [X] T031 [US1] Regenerate `docs/reference/benchmarks/coverage-comparison.md` by running `uv run python benchmarks/generate_all.py` and committing the output

### Tests (US1)

- [X] T032 [P] [US1] Integration test `tests/integration/test_atlas_coverage_script.py` — runs `atlas_coverage.py`, asserts JSON matches schema, asserts byte-identical output on two runs (determinism), asserts exit 0 when all mapped
- [X] T033 [P] [US1] Integration test `tests/integration/test_cli_atlas_filter.py` — valid technique → non-empty; invalid technique → exit 2 with suggestion; combined `--atlas X --owasp Y` AND semantics
- [X] T034 [P] [US1] Integration test `tests/integration/test_report_atlas_section.py` — run a synthetic campaign, assert Markdown and HTML reports include per-finding ATLAS ID and the ATLAS coverage section
- [ ] T035 [US1] Unit test extension in `tests/unit/test_library_atlas_filter.py` — assert `lint_atlas_coverage()` returns empty list after retro-mapping

**Checkpoint**: US1 fully deliverable. Every vector has an ATLAS mapping, `atlas_coverage.py` passes, CLI filter works, reports surface the mapping, benchmark comparison table shows the new row.

---

## Phase 4: User Story 2 — Complete OWASP LLM Top 10 coverage (Priority: P1)

**Goal**: OWASP coverage dashboard reports all 10 categories at "strong" or "comprehensive". LLM05 (≥10) and LLM10 (≥10) are closed out. All new vectors carry both OWASP and ATLAS mappings.

**Independent Test**: Run `uv run python benchmarks/owasp_coverage.py` — every category shows `strong` or `comprehensive`; no `moderate`, `planned`, or `not covered`. Run `ziran library --owasp LLM10` — returns ≥ 10 vectors.

### New attack vector YAML files

- [ ] T036 [P] [US2] Create `ziran/application/attacks/vectors/supply_chain.yaml` with ≥ 10 vectors covering malicious tool/plugin manifests, typosquatted tool names, compromised dependency framings, RAG connector poisoning, and fine-tuning data exfiltration. Each vector carries `owasp_mapping: [LLM05]` and `atlas_mapping:` with one or more techniques from the supply-chain family
- [ ] T037 [P] [US2] Create `ziran/application/attacks/vectors/model_theft.yaml` with ≥ 10 vectors covering systematic API querying for model extraction, weight approximation probes, fine-tuning data extraction (memorisation probes), model fingerprinting, and fine-tuning inversion prompts. Each vector carries `owasp_mapping: [LLM10]` and `atlas_mapping:` with exfiltration/reconnaissance techniques

### Benchmark script updates

- [ ] T038 [US2] Update `benchmarks/owasp_coverage.py`: remove entries for `"LLM05"` and `"LLM10"` from `_PLANNED_ISSUES`; add a strict floor check that every category is at `_STRONG` or better, emitting exit 1 on violation
- [ ] T039 [US2] Regenerate `docs/reference/benchmarks/coverage-comparison.md` and `benchmarks/results/owasp_coverage.json` (via `benchmarks/generate_all.py`)

### Tests (US2)

- [ ] T040 [P] [US2] Unit test extension in `tests/unit/test_owasp_coverage.py` asserting LLM05 count ≥ 10, LLM10 count ≥ 10, and strict floor across all 10 categories (add the test file if it does not yet exist — parallel to `benchmarks/owasp_coverage.py` coverage logic)
- [ ] T041 [P] [US2] Integration test `tests/integration/test_owasp_full_coverage.py` asserting `ziran library --owasp LLM05` and `--owasp LLM10` both return ≥ 10 vectors and every one carries a non-empty `atlas_mapping`

**Checkpoint**: OWASP coverage is 10/10. US2 deliverable independent of US3, US4, US5.

---

## Phase 5: User Story 3 — Demonstrably higher coverage on public benchmarks (Priority: P2)

**Goal**: TensorTrust, WildJailbreak, ToolEmu, and CyberSecEval rows on the benchmark comparison table show measurable increases. New vectors cover unique pattern families, not raw count parity.

**Independent Test**: Regenerate the coverage-comparison.md. Inspect the four rows — numerator increased versus the pre-release baseline. Run `ziran library --tag tensortrust` (and similar for other benchmarks) — each returns the expected count of new vectors.

### New attack vector YAML files

- [ ] T042 [P] [US3] Create `ziran/application/attacks/vectors/tensortrust_patterns.yaml` with ~25 vectors spanning system-prompt override, credential extraction, tool-output substitution, fake-rulebook framings, and multi-language injection. Each carries `owasp_mapping: [LLM01]`, `atlas_mapping:` with prompt-injection techniques, and `tags: [tensortrust]`
- [ ] T043 [P] [US3] Create `ziran/application/attacks/vectors/wildjailbreak_tactics.yaml` with ~10 new multi-turn tactics (progressive hypothetical escalation, persona rewind, compliance weaponisation, moral inversion, Socratic induction). Each carries `owasp_mapping: [LLM01]` and appropriate ATLAS techniques; tag `wildjailbreak`
- [ ] T044 [P] [US3] Create `ziran/application/attacks/vectors/toolemu_sandbox.yaml` with ~15 sandbox-evasion vectors (filesystem-path tricks, process spawn, network-egress probes, sandbox-fingerprinting). Distinct from generic tool-manipulation; tag `toolemu`
- [ ] T045 [P] [US3] Create `ziran/application/attacks/vectors/cyberseceval_codegen.yaml` with ~20 vectors split between code-generation safety (unsafe code requests, insecure-pattern solicitation) and cybersecurity knowledge (CVE elicitation, exploit-detail probing); tag `cyberseceval`

### Benchmark script updates

- [ ] T046 [US3] Update `benchmarks/benchmark_comparison.py` to reflect new vector counts for TensorTrust, WildJailbreak, ToolEmu, and CyberSecEval rows. Replace the "Not yet implemented" LLMail-Inject row with a RAG injection row pointing to the new `rag_poisoning.yaml` (deliverable completed in US4 — tolerate zero when US4 has not landed yet via a late-binding count)
- [ ] T047 [US3] Regenerate `docs/reference/benchmarks/coverage-comparison.md` via `benchmarks/generate_all.py`

### Tests (US3)

- [ ] T048 [P] [US3] Integration test `tests/integration/test_benchmark_tag_filters.py` asserting `ziran library --tag tensortrust`, `--tag wildjailbreak`, `--tag toolemu`, and `--tag cyberseceval` each return the expected vector counts and all vectors in each subset carry ATLAS and OWASP mappings

**Checkpoint**: US3 deliverable. Benchmark comparison table shows measurable lifts.

---

## Phase 6: User Story 4 — Detect retrieval-targeted prompt injection in RAG systems (Priority: P2)

**Goal**: New `rag_poisoning.yaml` in the indirect-injection category with retrieval-optimised payloads across multiple document-format framings.

**Independent Test**: `ziran library --tag rag-poisoning` returns the new vectors. Every vector carries `category: indirect_injection`, `owasp_mapping: [LLM01]`, and an ATLAS indirect-injection technique mapping. Sample payloads are keyword-dense and framed for multiple document types (email / web page / database record).

- [ ] T049 [US4] Create `ziran/application/attacks/vectors/rag_poisoning.yaml` with ~12 vectors. Each uses `category: indirect_injection`, `tags: [rag-poisoning]`, `owasp_mapping: [LLM01]`, and an ATLAS indirect-injection technique. Include three vectors per document framing: email, web page, database record, knowledge-base article
- [ ] T050 [US4] Update `benchmarks/benchmark_comparison.py` to populate the RAG-injection row's numerator from the new file (late-binding via library query, not hardcoded count)
- [ ] T051 [P] [US4] Integration test `tests/integration/test_rag_poisoning_filter.py` asserting `--tag rag-poisoning` returns the expected vectors, every vector carries the OWASP + ATLAS mappings declared in the spec, and each of the four document framings is represented at least once

**Checkpoint**: US4 deliverable independently. RAG poisoning vectors discoverable and runnable via existing CLI.

---

## Phase 7: User Story 5 — Measure attacks that bypass active defences (Priority: P3)

**Goal**: Campaign configuration accepts an optional defence profile. When a non-empty profile is declared, the campaign report carries a `defence_profile` block and — if evaluable defences exist — an `evasion_rate`. When no profile is declared, the report is byte-identical to a pre-release report (no defence or evasion fields).

**Independent Test**: Run `ziran scan --target <agent> --defence-profile profiles/sample.yaml` — report includes declared defences and (since no evaluable defences ship in this release) "not computable" notation in Markdown/HTML. Run the same command without `--defence-profile` — report contains zero defence/evasion content.

### Domain additions

- [ ] T052 [US5] Create `ziran/domain/entities/defence.py` containing `DefenceProfile` (name, defences list) and `DefenceDeclaration` (kind literal, identifier, evaluable=False default) Pydantic models per `contracts/defence-profile-yaml.md`
- [ ] T053 [US5] Extend `CampaignResult` (locate in existing domain/entities — the campaign/phase module) with `defence_profile: DefenceProfile | None = None` and `evasion_rate: float | None = None`. Ensure the model's serialisation excludes `None` fields (use `model_config` with `ConfigDict(exclude_none=True)` at JSON-dump time, or call `model_dump(exclude_none=True)` in the report pipeline)

### Application layer

- [ ] T054 [US5] Create `ziran/application/campaign/__init__.py` (if absent) and `ziran/application/campaign/evasion.py` implementing `compute_evasion_rate(findings, profile) -> float | None` with the 4-case logic documented in `data-model.md` (None profile, empty profile, no evaluable defences, evaluable defences)
- [ ] T055 [US5] Wire defence-profile loading in the scan CLI: add `--defence-profile <path>` option to `ziran/interfaces/cli/main.py` scan subcommand; accept inline `defence_profile:` key in scan config YAML; flag wins on conflict (log warning). Load via `DefenceProfile.model_validate(yaml.safe_load(path))`
- [ ] T056 [US5] Wire `compute_evasion_rate` into the campaign finalisation step. Locate where `CampaignResult` is built at end-of-campaign and call the helper to populate `evasion_rate` and echo the loaded `defence_profile`

### Report surface

- [ ] T057 [US5] Extend Markdown report template in `ziran/interfaces/cli/reports.py` with a conditional "Declared Defences" section (table: kind / identifier / evaluable) and an Evasion-rate row. When no profile is declared, emit nothing (preserve byte-identity with pre-release reports)
- [ ] T058 [US5] Mirror T057 in the HTML report template

### Tests (US5)

- [ ] T059 [P] [US5] Unit test `tests/unit/test_defence_profile.py` — Pydantic validation of `DefenceProfile` / `DefenceDeclaration` (required fields, literal constraint on `kind`, default `evaluable=False`)
- [ ] T060 [P] [US5] Unit test `tests/unit/test_evasion_metric.py` — four cases (None profile, empty profile, profile with no evaluable defences, profile with evaluable defences using a mock count)
- [ ] T061 [P] [US5] Integration test `tests/integration/test_campaign_with_defence.py` — run a synthetic campaign with a sample profile; assert declared-defences section appears in MD and JSON; assert `evasion_rate` is omitted from JSON but the report explains "not computable"
- [ ] T062 [P] [US5] Integration test `tests/integration/test_campaign_without_defence.py` — run the same campaign without `--defence-profile`; assert the JSON output contains no `defence_profile` or `evasion_rate` keys (byte-identity preserved)

**Checkpoint**: US5 deliverable. Defence profile schema + evasion-rate metric field is in place and report-facing. Future releases can add real evaluators without schema change.

---

## Phase 8: Polish & Release Readiness

**Purpose**: Cross-cutting work, documentation, determinism validation, and the final quality-gate run.

### Documentation

- [ ] T063 Create `docs/reference/benchmarks/atlas-mapping.md` explaining how ATLAS mapping is structured, the snapshot date (October 2025), how to interpret the coverage dashboard, and links to the MITRE ATLAS website. Register the page in `mkdocs.yml`
- [ ] T064 [P] Update `README.md` "Benchmark Coverage" or equivalent section to mention ATLAS coverage alongside OWASP (one short paragraph + link to the atlas-mapping.md doc)
- [ ] T065 [P] Add a release-notes entry in `CHANGELOG.md` (release-please will regenerate this — manual edit if needed to record: ATLAS mapping added, OWASP coverage 10/10, benchmark expansion, RAG poisoning category, defence-profile schema)

### Regeneration and determinism

- [ ] T066 Run `uv run python benchmarks/generate_all.py` to regenerate `benchmarks/results/*.json` and `docs/reference/benchmarks/coverage-comparison.md` in a clean state; commit the updated artefacts
- [ ] T067 Manually verify determinism: hash `benchmarks/results/*.json` with `sha256sum`, run `benchmarks/generate_all.py` a second time, re-hash, confirm the hashes match byte-for-byte. Fix any non-determinism discovered (most likely: dict iteration order in `atlas_coverage.py` or similar) before proceeding

### Quality gates

- [ ] T068 Run `uv run ruff check .` and fix any new violations
- [ ] T069 Run `uv run ruff format --check .` and re-format if drift detected
- [ ] T070 Run `uv run mypy ziran/` and fix any strict-mode errors introduced
- [ ] T071 Run `uv run pytest --cov=ziran` and confirm total coverage ≥ 85%. Investigate any module that regressed below 85% and add tests to close the gap

### Acceptance validation

- [ ] T072 Walk through every numbered section in `specs/012-benchmark-maturity/quickstart.md` end-to-end (manual QA). Any step that doesn't produce the documented output is a bug — fix and re-walk

**Checkpoint**: Release-ready. Ready to open PRs per the packaging strategy in `plan.md` (5-PR split).

---

## Dependencies & Execution Order

### Phase dependencies

- **Phase 1 (Setup)**: no dependencies.
- **Phase 2 (Foundational)**: depends on Phase 1. **Blocks** Phases 3, 4, 5, 6 (all ATLAS-touching stories).
- **Phase 3 (US1)**: depends on Phase 2. Also depends on T014 (enum expansion) before any retro-mapping task can annotate a vector with a specific technique.
- **Phases 4, 5, 6 (US2, US3, US4)**: depend on Phase 2. Parallel with each other and with Phase 3, but their YAML files should not conflict (each creates a new file, no file overlap).
- **Phase 7 (US5)**: independent of Phases 3–6. Depends only on Phase 1. Can run in parallel with any ATLAS story.
- **Phase 8 (Polish)**: depends on all desired user-story phases completing.

### User-story dependencies

- **US1 (P1)**: blocks nothing else by contract; however the CI lint (`lint_atlas_coverage`) only hard-fails after US1's retro-mapping pass lands. Until then, US2/US3/US4 new vectors must still carry non-empty `atlas_mapping` to avoid blocking when the CI gate flips strict.
- **US2 (P1)**: independent of US1; new vectors must carry ATLAS mapping — the Phase 2 enum must cover supply-chain + model-theft techniques.
- **US3 (P2)**: independent of US1 and US2; same enum requirement.
- **US4 (P2)**: independent. Benchmark-comparison row (T050) prefers late-binding via library query so US3's T046 doesn't block.
- **US5 (P3)**: fully independent.

### Parallel opportunities

- **Foundational**: T002–T006 are sequential (same file, ordering-sensitive). T007/T008 can run in parallel (same file, but straightforward to merge). T011/T012/T013 are independent tests → parallel.
- **US1 retro-mapping**: T015–T023 all edit different YAML files → all `[P]`, all parallel.
- **US1 surface**: T027–T030 touch different files (CLI vs reports) → parallel where noted.
- **US2/US3/US4 new YAML**: T036, T037, T042, T043, T044, T045, T049 are each a new file → all `[P]`, all parallel.
- **US5 tests**: T059–T062 are independent files → parallel.

---

## Parallel Example: US1 retro-mapping pass

```bash
# After T014 (enum expansion) lands, launch every annotation task in parallel:
Task: "Annotate ziran/application/attacks/vectors/prompt_injection.yaml"
Task: "Annotate prompt-injection family: jailbreakbench.yaml, multi_turn_tactics.yaml, expanded_tactics.yaml"
Task: "Annotate chain_of_thought_manipulation.yaml and memory_poisoning.yaml"
Task: "Annotate indirect-injection family: indirect_injection.yaml, indirect_injection_escalation.yaml, indirect_injection_exfiltration.yaml, indirect_injection_tool_abuse.yaml"
Task: "Annotate mcp_attacks.yaml, mcp_attacks_expanded.yaml, model_dos.yaml"
Task: "Annotate data_exfiltration.yaml and system_prompt_extraction.yaml"
Task: "Annotate authorization.yaml and privilege_escalation.yaml"
Task: "Annotate multi_agent.yaml, a2a_attacks.yaml, rjudge.yaml"
Task: "Annotate harmful_tasks.yaml, harmful_tasks_expanded.yaml, alert_coverage.yaml"
```

---

## Implementation Strategy

### MVP first (US1 only)

1. Complete Phase 1 (Setup) — ~5 min.
2. Complete Phase 2 (Foundational) — the enum, mapping fields, library helpers. Ships as **PR #1**.
3. Complete Phase 3 (US1) — retro-map every vector, add `atlas_coverage.py`, CLI filter, report surface. Ships as **PR #2**.
4. **STOP and VALIDATE**: Run quickstart sections 1–5. Demo ATLAS coverage to anyone who cares. v0.27 could ship here if we want the milestone closed in two releases instead of one.

### Incremental delivery (full milestone)

1. **PR #1** — Phases 1 + 2 (Foundation).
2. **PR #2** — Phase 3 (US1 ATLAS mapping + surface).
3. **PR #3** — Phases 4 + 5 + 6 (US2 + US3 + US4 — all YAML-heavy, minimal code churn, reviewed together).
4. **PR #4** — Phase 7 (US5 defence profile + evasion rate).
5. **PR #5** — Phase 8 (polish, regen, release notes).

### Parallel team strategy

If staffed with 2–3 engineers:

1. Engineer A: Phase 2 foundation, then PR #2 (US1 retro-mapping + surface).
2. Engineer B: Phase 2 review, then PR #3 (US2 + US3 + US4 YAML work).
3. Engineer C (if available): PR #4 (US5 — schema + wiring + tests).
4. All converge on PR #5 for regeneration and release.

---

## Notes

- `[P]` tasks edit different files, have no in-flight dependency on other `[P]` tasks in the same phase.
- `[Story]` labels map tasks to user stories for PR-scope tracing.
- Every new vector added in US2/US3/US4/US6 MUST carry both `owasp_mapping` and `atlas_mapping` from day one (don't accumulate new debt).
- Determinism check (T067) is non-optional: downstream signing (issue #259) relies on byte-identity.
- No `Co-Authored-By: Claude` trailers in any commit on this branch (constitution + user preference).
- Every PR must include a GitHub label indicating its scope (e.g., `benchmark`, `cli`, `docs`) — see user memory on PR labels.
