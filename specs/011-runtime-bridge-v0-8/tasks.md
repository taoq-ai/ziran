# Tasks: v0.8 — Runtime Bridge and Positioning

**Input**: Design documents from `/specs/011-runtime-bridge-v0-8/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Included — FR-025 and constitution require automated tests for all new commands (coverage ≥ 85%).

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization — new package directories and optional dependency registration

- [x] T001 Create new package directories: `ziran/domain/entities/policy.py`, `ziran/domain/entities/trace.py`, `ziran/domain/entities/registry.py`, `ziran/domain/ports/policy_renderer.py`, `ziran/domain/ports/trace_ingestor.py`, `ziran/domain/ports/snapshot_store.py`
- [x] T002 [P] Create new package directories: `ziran/application/policy_export/__init__.py`, `ziran/application/trace_analysis/__init__.py`, `ziran/application/registry_watch/__init__.py`
- [x] T003 [P] Create new package directories: `ziran/infrastructure/policy_renderers/__init__.py`, `ziran/infrastructure/trace_ingestors/__init__.py`, `ziran/infrastructure/snapshot_stores/__init__.py`
- [x] T004 [P] Add `langfuse` optional dependency group to `pyproject.toml` under `[project.optional-dependencies]`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Shared domain model extensions used by multiple user stories

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [x] T005 Extend `DangerousChain` dataclass in `ziran/domain/entities/capability.py` with optional trace-evidence fields: `observed_in_production: bool = False`, `first_seen: datetime | None = None`, `last_seen: datetime | None = None`, `occurrence_count: int = 0`, `trace_source: str | None = None`
- [x] T006 Extend `CampaignResult` model in `ziran/domain/entities/phase.py` with `source: str = "scan"` discriminator field
- [x] T007 Add unit tests verifying backward compatibility of extended models in `tests/unit/test_domain_extensions.py` — existing serialization/deserialization must not break

**Checkpoint**: Foundation ready — extended models pass existing tests + new backward-compat tests. User story implementation can now begin in parallel.

---

## Phase 3: User Story 1 — Export Findings as Guardrail Policies (Priority: P1) 🎯 MVP

**Goal**: A user with a campaign result file runs `ziran export-policy --format rego` and gets a ready-to-apply policy bundle.

**Independent Test**: `ziran export-policy --result tests/fixtures/sample_campaign_result.json --format rego --out /tmp/policies/` produces a valid `.rego` file with finding-ID header and deny rule matching the tool-call sequence.

### Domain Layer

- [x] T008 [P] [US1] Create `PolicyFormat` enum and `GuardrailPolicy` Pydantic model in `ziran/domain/entities/policy.py` per data-model.md
- [x] T009 [P] [US1] Create `PolicyRenderer` ABC port in `ziran/domain/ports/policy_renderer.py` with `render(finding: DangerousChain) -> GuardrailPolicy` method

### Tests

- [x] T010 [P] [US1] Write unit tests for Rego renderer in `tests/unit/test_rego_renderer.py` — verify valid Rego syntax, finding-ID comment header, deny rule for canonical `read_file → http_request` chain
- [x] T011 [P] [US1] Write unit tests for Cedar renderer in `tests/unit/test_cedar_renderer.py` — verify forbid policy with context assumption comment
- [x] T012 [P] [US1] Write unit tests for Colang renderer in `tests/unit/test_colang_renderer.py` — verify `define flow` block with sequential `match` and `abort`
- [x] T013 [P] [US1] Write unit tests for Invariant renderer in `tests/unit/test_invariant_renderer.py` — verify `raise` rule with `->` temporal operator
- [x] T014 [P] [US1] Write unit test for ExportService in `tests/unit/test_export_service.py` — severity floor filtering, skip counting, empty result handling

### Infrastructure Layer

- [x] T015 [P] [US1] Implement `RegoRenderer` adapter in `ziran/infrastructure/policy_renderers/rego_renderer.py` — generate OPA deny rules keyed on tool-call sequence array indexing
- [x] T016 [P] [US1] Implement `CedarRenderer` adapter in `ziran/infrastructure/policy_renderers/cedar_renderer.py` — generate forbid policies with context-based previous-tool tracking
- [x] T017 [P] [US1] Implement `ColangRenderer` adapter in `ziran/infrastructure/policy_renderers/colang_renderer.py` — generate Colang 2.0 `define flow` blocks with sequential `match ToolCall` + `abort`
- [x] T018 [P] [US1] Implement `InvariantRenderer` adapter in `ziran/infrastructure/policy_renderers/invariant_renderer.py` — generate `raise` rules with `->` temporal ordering

### Application Layer

- [x] T019 [US1] Implement `ExportService` in `ziran/application/policy_export/export_service.py` — load campaign result, filter by severity floor, iterate findings, delegate to renderer, collect skip reasons, return list of `GuardrailPolicy`

### Interface Layer

- [x] T020 [US1] Implement `export-policy` click subcommand in `ziran/interfaces/cli/export_policy.py` per CLI contract — `--result`, `--format`, `--out`, `--severity-floor`, `--verbose` options
- [x] T021 [US1] Register `export-policy` subcommand in `ziran/interfaces/cli/main.py`

### Integration Test

- [x] T022 [US1] Write CLI integration test in `tests/integration/test_export_policy_cli.py` — invoke `ziran export-policy` with sample campaign result fixture, verify output files exist with correct headers for each format

**Checkpoint**: `ziran export-policy` works end-to-end for all four formats. Tests pass. Story 1 is independently functional.

---

## Phase 4: User Story 2 — Analyze Production Traces (Priority: P1)

**Goal**: A user with an OTel or Langfuse trace file runs `ziran analyze-traces` and gets a findings report annotated with production evidence.

**Independent Test**: `ziran analyze-traces --source otel --input tests/fixtures/sample_otel_traces.jsonl --out /tmp/reports/` produces a report with findings marked "observed in production" with timestamps and occurrence counts.

### Domain Layer

- [x] T023 [P] [US2] Create `TraceSession` and `ToolCallEvent` Pydantic models in `ziran/domain/entities/trace.py` per data-model.md
- [x] T024 [P] [US2] Create `TraceIngestor` ABC port in `ziran/domain/ports/trace_ingestor.py` with `async def ingest(source: Path | str) -> list[TraceSession]` method

### Fixtures

- [x] T025 [P] [US2] Create synthetic OTel JSONL trace fixture in `tests/fixtures/sample_otel_traces.jsonl` — at least 3 traces: one with `read_file → http_request` dangerous chain, one clean, one with multi-agent interleaved sessions
- [x] T026 [P] [US2] Create synthetic Langfuse JSON trace fixture in `tests/fixtures/sample_langfuse_traces.json` — matching patterns to OTel fixture for parity testing

### Tests

- [x] T027 [P] [US2] Write unit tests for OTel ingestor in `tests/unit/test_otel_ingestor.py` — verify span parsing, session grouping by traceId, tool-call extraction via `gen_ai.tool.name` attribute, timestamp ordering
- [x] T028 [P] [US2] Write unit tests for Langfuse ingestor in `tests/unit/test_langfuse_ingestor.py` — verify observation parsing, session grouping by sessionId, tool-call extraction from SPAN observations
- [x] T029 [P] [US2] Write unit test for AnalyzerService in `tests/unit/test_analyzer_service.py` — verify temp graph construction, `ToolChainAnalyzer` reuse, trace-evidence annotation (observed_in_production, timestamps, counts), cross-session deduplication

### Infrastructure Layer

- [x] T030 [P] [US2] Implement `OTelIngestor` adapter in `ziran/infrastructure/trace_ingestors/otel_ingestor.py` — parse JSONL ResourceSpans, group by traceId, extract tool-call spans via `gen_ai.tool.name` semantic convention, sort by startTimeUnixNano
- [x] T031 [P] [US2] Implement `LangfuseIngestor` adapter in `ziran/infrastructure/trace_ingestors/langfuse_ingestor.py` — support file-export JSON parsing AND API pull mode via `langfuse.Langfuse().fetch_traces()`. Raise clear error if `langfuse` package not installed.

### Application Layer

- [x] T032 [US2] Implement `AnalyzerService` in `ziran/application/trace_analysis/analyzer_service.py` — for each TraceSession: build temporary `AttackKnowledgeGraph` with tool nodes + `CAN_CHAIN_TO` edges, run `ToolChainAnalyzer.analyze()`, annotate `DangerousChain` results with trace metadata, aggregate across sessions

### Interface Layer

- [x] T033 [US2] Implement `analyze-traces` click subcommand in `ziran/interfaces/cli/analyze_traces.py` per CLI contract — `--source`, `--input`, `--project-id`, `--since`, `--out`, `--format`, `--verbose` options
- [x] T034 [US2] Register `analyze-traces` subcommand in `ziran/interfaces/cli/main.py`

### Integration Test

- [x] T035 [US2] Write CLI integration test in `tests/integration/test_analyze_traces_cli.py` — invoke `ziran analyze-traces` with OTel fixture, verify report contains "observed in production" findings with correct timestamps and occurrence counts

**Checkpoint**: `ziran analyze-traces` works end-to-end for OTel and Langfuse. Tests pass. Story 2 is independently functional.

---

## Phase 5: User Story 3 — Watch MCP Registries for Drift (Priority: P2)

**Goal**: A developer runs `ziran watch-registry --config registry.yaml` and detects added tools, description changes, and typosquatted server names.

**Independent Test**: Given two fixture manifests where the second adds a tool and modifies a description, the watcher detects both changes and writes an updated snapshot.

### Domain Layer

- [x] T036 [P] [US3] Create `ManifestSnapshot`, `ToolDescriptor`, `DriftFinding`, `RegistryConfig`, `ServerEntry` Pydantic models in `ziran/domain/entities/registry.py` per data-model.md
- [x] T037 [P] [US3] Create `SnapshotStore` ABC port in `ziran/domain/ports/snapshot_store.py` with `load(server_name) -> ManifestSnapshot | None` and `save(server_name, snapshot)` methods

### Fixtures

- [x] T038 [P] [US3] Create MCP manifest fixture files in `tests/fixtures/`: `mcp_manifest_v1.json` (baseline with 3 tools), `mcp_manifest_v2_drift.json` (adds 1 tool, modifies 1 description), `mcp_manifest_typosquat.json` (name similar to allowlist entry)

### Tests

- [x] T039 [P] [US3] Write unit tests for `TyposquatDetector` in `tests/unit/test_typosquat_detector.py` — verify Levenshtein distance detection, common substitution patterns (l/1, o/0, rn/m), exemption list handling, severity scoring by distance
- [x] T040 [P] [US3] Write unit tests for manifest diff logic in `tests/unit/test_registry_watcher.py` — verify detection of added tool, removed tool, description change, schema change, permission change; verify network error does not corrupt snapshot
- [x] T041 [P] [US3] Write unit tests for `JsonFileStore` in `tests/unit/test_json_file_store.py` — verify save/load round-trip, atomic write (no corruption on crash), missing snapshot returns None

### Infrastructure Layer

- [x] T042 [P] [US3] Implement `JsonFileStore` adapter in `ziran/infrastructure/snapshot_stores/json_file_store.py` — save/load ManifestSnapshot as JSON files in `.ziran/snapshots/{name}.json`, atomic write via temp file + rename

### Application Layer

- [x] T043 [US3] Implement `TyposquatDetector` in `ziran/application/registry_watch/typosquat_detector.py` — Levenshtein distance (pure Python, no new dependency) + common substitution patterns, configurable threshold (default ≤ 2), exemption list support
- [x] T044 [US3] Implement `WatcherService` in `ziran/application/registry_watch/watcher_service.py` — load config, fetch manifests via MCP protocol handler, diff against stored snapshots, run typosquat detection, emit DriftFinding list, update snapshots. Handle network errors gracefully (skip server, preserve snapshot).

### Interface Layer

- [x] T045 [US3] Implement `watch-registry` click subcommand in `ziran/interfaces/cli/watch_registry.py` per CLI contract — `--config`, `--snapshot-dir`, `--out`, `--format`, `--verbose` options
- [x] T046 [US3] Register `watch-registry` subcommand in `ziran/interfaces/cli/main.py`

### Integration Test

- [x] T047 [US3] Write CLI integration test in `tests/integration/test_watch_registry_cli.py` — invoke `ziran watch-registry` with fixture config and pre-stored snapshot, verify drift findings detected

### CI Example

- [x] T048 [US3] Create GitHub Action example for registry watcher in `examples/08-registry-watcher/watch-registry.yml` — runs `ziran watch-registry`, opens issue on drift via `gh issue create`

**Checkpoint**: `ziran watch-registry` works end-to-end. Drift detection and typosquatting tests pass. Story 3 is independently functional.

---

## Phase 6: User Story 4 — CI Templates for Non-GitHub Platforms (Priority: P2)

**Goal**: Teams on GitLab, Jenkins, CircleCI, and Azure Pipelines can copy a ready-to-use template and run Ziran as a quality gate.

**Independent Test**: Each template file is syntactically valid (lintable) and follows the same `essential | standard | comprehensive` coverage pattern as the GitHub Action.

### Implementation

- [x] T049 [P] [US4] Create GitLab CI template in `examples/07-cicd-quality-gate/gitlab-ci.yml` — `ziran ci` stage with coverage knob variable, SARIF upload to `gl-sast-report.json` artifact for Security Dashboard
- [x] T050 [P] [US4] Create Jenkins declarative pipeline template in `examples/07-cicd-quality-gate/Jenkinsfile` — `ziran ci` stage with coverage parameter, SARIF via Warnings NG plugin (`recordIssues tool: sarif()`)
- [x] T051 [P] [US4] Create CircleCI config template in `examples/07-cicd-quality-gate/circleci-config.yml` — `ziran ci` job with coverage parameter, SARIF as artifact
- [x] T052 [P] [US4] Create Azure Pipelines template in `examples/07-cicd-quality-gate/azure-pipelines.yml` — `ziran ci` task with coverage variable, SARIF upload via `PublishBuildArtifacts` + Advanced Security

### Lint Validation

- [x] T053 [US4] Add CI lint job to `.github/workflows/ci.yml` that validates all four CI template files on each push — YAML syntax check for GitLab/CircleCI/Azure, Groovy syntax check for Jenkinsfile

### Documentation

- [x] T054 [US4] Create `docs/guides/ci-integrations.md` with side-by-side snippets for all five CI systems (GitHub + four new), platform-specific SARIF upload instructions, and coverage knob documentation
- [x] T055 [US4] Update README "CI/CD Integration" section to list all five supported CI systems with links to templates

**Checkpoint**: All four CI templates exist, are linted in CI, and documented. Story 4 is independently functional.

---

## Phase 7: User Story 5 — Landscape Documentation (Priority: P3)

**Goal**: A user evaluating agent-security tools can see a three-layer diagram positioning Ziran alongside runtime governance and observability tools.

**Independent Test**: The landscape page renders correctly in mkdocs and contains the Mermaid diagram, OWASP mapping, and cross-links.

### Implementation

- [x] T056 [P] [US5] Create `docs/concepts/agent-security-landscape.md` with Mermaid three-layer diagram (pre-deploy: Ziran/Promptfoo/Garak, runtime: NeMo/Lakera/Invariant/AGT, observability: Langfuse/LangSmith/Phoenix), OWASP LLM vs Agentic Top 10 mapping, cross-links to export-policy and analyze-traces docs
- [x] T057 [P] [US5] Update README "Works With" section to add runtime governance tools row (NeMo, Lakera, Invariant, Microsoft AGT) explicitly framed as complements
- [x] T058 [US5] Add landscape page to mkdocs navigation sidebar in `mkdocs.yml`

**Checkpoint**: Landscape docs render correctly. Story 5 is independently functional.

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: Integration tests, documentation, and quality gates across all stories

- [x] T059 Create end-to-end test in `tests/integration/test_full_loop.py` — scan result → `export-policy` → verify valid policy files; trace fixture → `analyze-traces` → `export-policy` → verify policies from production-observed chains
- [x] T060 [P] Create `docs/guides/export-policy.md` with worked example per format (Rego, Cedar, Colang, Invariant)
- [x] T061 [P] Create `docs/guides/analyze-traces.md` with worked examples for OTel file, Langfuse file, and Langfuse API modes
- [x] T062 [P] Create `docs/guides/watch-registry.md` with worked example including registry.yaml config and drift detection output
- [x] T063 Run all quality gates: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`, `uv run pytest --cov=ziran` — fix any failures
- [x] T064 Verify coverage ≥ 85% — add missing tests if needed
- [x] T065 Run `quickstart.md` validation — execute each quickstart command against fixtures and verify expected output

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion — BLOCKS all user stories
- **US1 Policy Export (Phase 3)**: Depends on Foundational. No dependencies on other stories.
- **US2 Trace Analyzer (Phase 4)**: Depends on Foundational. No dependencies on other stories.
- **US3 Registry Watcher (Phase 5)**: Depends on Foundational. No dependencies on other stories.
- **US4 CI Templates (Phase 6)**: No dependencies on Foundational — can start after Setup.
- **US5 Landscape Docs (Phase 7)**: No dependencies on Foundational — can start after Setup. Cross-links to US1/US2 docs added in Polish phase.
- **Polish (Phase 8)**: Depends on all user stories being complete.

### User Story Dependencies

```
Phase 1 (Setup)
    │
    ▼
Phase 2 (Foundational) ──────────────────────┐
    │                                          │
    ├──► Phase 3 (US1: Policy Export) ◄──┐     │
    ├──► Phase 4 (US2: Trace Analyzer)   │     │
    └──► Phase 5 (US3: Registry Watcher) │     │
                                         │     │
Phase 1 (Setup) ─────────────────────────┤     │
    ├──► Phase 6 (US4: CI Templates)     │     │
    └──► Phase 7 (US5: Landscape Docs)   │     │
                                         │     │
                          All complete ──►│     │
                                         ▼     │
                               Phase 8 (Polish)│
```

### Within Each User Story

- Domain models before tests (test imports depend on models)
- Tests before infrastructure/application (TDD: tests fail first)
- Infrastructure adapters before application services (services depend on adapters)
- Application services before CLI commands (CLI delegates to services)
- CLI registration after CLI implementation
- Integration tests after CLI is registered

### Parallel Opportunities

- **Phase 1**: T001, T002, T003, T004 can all run in parallel
- **Phase 3 (US1)**: T008-T009 (domain) in parallel; T010-T014 (tests) all in parallel; T015-T018 (renderers) all in parallel
- **Phase 4 (US2)**: T023-T024 (domain) in parallel; T025-T026 (fixtures) in parallel; T027-T029 (tests) in parallel; T030-T031 (ingestors) in parallel
- **Phase 5 (US3)**: T036-T037 (domain) in parallel; T039-T041 (tests) all in parallel
- **Phase 6 (US4)**: T049-T052 (templates) all in parallel
- **Phase 7 (US5)**: T056-T057 in parallel
- **Cross-story**: US1, US2, US3 can all proceed in parallel after Phase 2. US4 and US5 can proceed in parallel after Phase 1 (no foundational dependency).

---

## Parallel Example: User Story 1

```bash
# Launch domain models in parallel:
Task: "T008 Create PolicyFormat enum and GuardrailPolicy model in ziran/domain/entities/policy.py"
Task: "T009 Create PolicyRenderer ABC port in ziran/domain/ports/policy_renderer.py"

# Launch all test files in parallel:
Task: "T010 Write unit tests for Rego renderer in tests/unit/test_rego_renderer.py"
Task: "T011 Write unit tests for Cedar renderer in tests/unit/test_cedar_renderer.py"
Task: "T012 Write unit tests for Colang renderer in tests/unit/test_colang_renderer.py"
Task: "T013 Write unit tests for Invariant renderer in tests/unit/test_invariant_renderer.py"
Task: "T014 Write unit test for ExportService in tests/unit/test_export_service.py"

# Launch all renderers in parallel:
Task: "T015 Implement RegoRenderer in ziran/infrastructure/policy_renderers/rego_renderer.py"
Task: "T016 Implement CedarRenderer in ziran/infrastructure/policy_renderers/cedar_renderer.py"
Task: "T017 Implement ColangRenderer in ziran/infrastructure/policy_renderers/colang_renderer.py"
Task: "T018 Implement InvariantRenderer in ziran/infrastructure/policy_renderers/invariant_renderer.py"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL — blocks US1/US2/US3)
3. Complete Phase 3: User Story 1 (Policy Export)
4. **STOP and VALIDATE**: `ziran export-policy --result fixture.json --format rego` works end-to-end
5. Deploy/demo if ready

### Incremental Delivery

1. Setup + Foundational → Foundation ready
2. Add US1 (Policy Export) → Test independently → MVP!
3. Add US2 (Trace Analyzer) → Test independently → "Full loop" enabled
4. Add US3 (Registry Watcher) → Test independently → Supply-chain coverage
5. Add US4 + US5 (CI + Docs) → Test independently → Adoption enablers
6. Polish → Quality gates pass → v0.8 release

### Parallel Team Strategy

With multiple developers after Phase 2:
- **Developer A**: US1 (Policy Export) — P1 core
- **Developer B**: US2 (Trace Analyzer) — P1 core
- **Developer C**: US3 (Registry Watcher) + US4 (CI Templates) — P2 breadth
- **Developer D**: US5 (Landscape Docs) + Polish — P3 narrative

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story is independently completable and testable
- Tests are written before implementation (TDD)
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Quality gates (`ruff check`, `ruff format`, `mypy`, `pytest --cov`) must pass before merge
