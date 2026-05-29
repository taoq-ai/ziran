---
description: "Task list for Runtime Loop Alerting and Automation"
---

# Tasks: Runtime Loop Alerting and Automation

**Input**: Design documents from `/specs/017-runtime-loop-alerting/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: INCLUDED — the spec's acceptance criteria explicitly require integration tests with a mock HTTP server (respx) and dedup/idempotency tests.

**Organization**: Tasks grouped by user story. The shared notification capability (port, entities, dispatcher, sinks, `!env` loader) is foundational because both US1 and US2 depend on it; US3 is fully independent.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: US1 / US2 / US3 (Setup/Foundational/Polish have no story label)

## Path Conventions

Single-project hexagonal layout: code in `ziran/`, tests in `tests/`.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project scaffolding for the alerting feature

- [X] T001 Add `respx` as a dev dependency in `pyproject.toml` (test group) and create the new package directories with `__init__.py`: `ziran/application/alerting/`, `ziran/infrastructure/alert_sinks/`, `ziran/infrastructure/config/`
- [X] T002 [P] Add shared respx + asyncio test fixtures (httpx transport mock, fake Slack webhook URL, fake GitHub API base) to `tests/conftest.py` or `tests/fixtures/alerting.py`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: The shared `AlertSink` notification capability reused by US1 and US2

**⚠️ CRITICAL**: US1 and US2 cannot begin until this phase is complete. (US3 is independent and may proceed in parallel.)

- [X] T003 [P] Create alerting domain entities (`AlertableFinding`, `AlertLink`, `DeliveryResult`, `AlertOutcome`) and pure fingerprint helpers (`drift_fingerprint`, `trace_fingerprint`, `digest_fingerprint`) in `ziran/domain/entities/alerting.py` per data-model.md
- [X] T004 [P] Define the `AlertSink` ABC (`name`, `async emit(finding) -> DeliveryResult`) in `ziran/domain/ports/alert_sink.py` per contracts/alert_sink_port.md
- [X] T005 [P] Implement the `!env VAR_NAME` YAML loader/constructor (plus `${VAR}` interpolation) in `ziran/infrastructure/config/env_yaml.py`, raising a clear error on unset vars (research R4)
- [X] T006 [P] Implement `AlertSinkConfig` and `AlertConfig` Pydantic models (with kind-conditional validation) in `ziran/application/alerting/config.py` per data-model.md
- [X] T007 Implement the dispatcher in `ziran/application/alerting/dispatch.py`: severity-floor filtering, `asyncio.gather` fan-out, partial-failure aggregation into `AlertOutcome` (depends on T003, T004)
- [X] T008 [P] Implement the `DryRunSink` wrapper in `ziran/infrastructure/alert_sinks/dry_run_sink.py` (prints payload, zero I/O) (depends on T004)
- [X] T009 Implement `SlackWebhookSink` in `ziran/infrastructure/alert_sinks/slack_sink.py` (httpx, Block Kit + text fallback) per contracts/sinks_http.md (depends on T003, T004)
- [X] T010 Implement `GitHubIssueSink` in `ziran/infrastructure/alert_sinks/github_issue_sink.py` (httpx REST: marker-search dedup → create, fingerprint marker in body) per contracts/sinks_http.md (depends on T003, T004)
- [X] T011 Implement the sink factory (`AlertConfig` → list of concrete sinks, wrapping in `DryRunSink` when dry-run) in `ziran/application/alerting/factory.py` (depends on T006, T008, T009, T010)
- [X] T012 [P] Unit tests for fingerprint helpers + severity-floor/dry-run/partial-failure aggregation in `tests/unit/test_alert_fingerprint.py` and `tests/unit/test_alert_dispatch.py`
- [X] T013 [P] Unit tests for the `!env` loader (resolve, unset-var error, `${VAR}`) in `tests/unit/test_env_yaml.py`
- [X] T014 [P] Integration test (respx) asserting Slack request shape in `tests/integration/test_slack_sink.py`
- [X] T015 [P] Integration test (respx) asserting GitHub create + marker-search dedup idempotency (zero duplicate POST on re-run) in `tests/integration/test_github_issue_sink.py`

**Checkpoint**: Shared notification capability complete and tested — US1/US2 can begin.

---

## Phase 3: User Story 1 - Registry drift reaches a human (Priority: P1) 🎯 MVP

**Goal**: `watch-registry` delivers every drift finding to configured Slack/GitHub sinks, with severity floors, dry-run, and stateless dedup.

**Independent Test**: Configure a watcher with both sinks against respx endpoints, introduce a drift event in a mock snapshot, run the watcher → assert a formatted Slack message and one GitHub issue; re-run with no new drift → nothing new sent.

### Tests for User Story 1

- [X] T016 [P] [US1] Integration test (respx) for `watch-registry` end-to-end alerting + dedup on re-run in `tests/integration/test_watch_registry_alerting.py`
- [X] T017 [P] [US1] Unit test for `DriftFinding.fingerprint()` = `(server, tool, drift-kind)` and `to_alertable()` mapping in `tests/unit/test_drift_alertable.py`

### Implementation for User Story 1

- [X] T018 [US1] Add `fingerprint()` and `to_alertable()` to `DriftFinding` in `ziran/domain/entities/registry.py`: emit before/after values as inline `fields`, and add a snapshot-diff `AlertLink` only when a remote-resolvable URL exists (else rely on the inline summary, per FR-011) (depends on T003)
- [X] T019 [US1] Extend the registry config model + loader to parse the `alerts:` block using the `!env` loader in `ziran/application/registry_watch/` config + `ziran/infrastructure/config/env_yaml.py` (depends on T005, T006)
- [X] T020 [US1] Extend `watch(...)` to accept `alert_sinks` + `dry_run_alerts`, map findings via `to_alertable()`, and dispatch in `ziran/application/registry_watch/watcher_service.py` (depends on T007, T018)
- [X] T021 [US1] Wire the `watch-registry` CLI: build sinks from config via factory, add `--dry-run-alerts`, map `AlertOutcome` to the exit-code contract (0/2/1, preserving the existing severity-gate) in `ziran/interfaces/cli/watch_registry.py` (depends on T011, T020)

**Checkpoint**: US1 fully functional and independently testable — MVP ready.

---

## Phase 4: User Story 2 - Dangerous production behavior files a tracked issue (Priority: P2)

**Goal**: `analyze-traces` opens (deduped) GitHub issues for dangerous chains observed in production, with full context, optional remediation, and a digest mode.

**Independent Test**: Feed synthetic trace fixtures with one novel dangerous-chain execution + a GitHub sink → assert exactly one issue with required content; re-run → zero new issues.

### Tests for User Story 2

- [ ] T022 [P] [US2] Integration test (respx) for `analyze-traces` per-session issue + dedup on re-run in `tests/integration/test_analyze_traces_alerting.py`
- [ ] T023 [P] [US2] Unit test for trace fingerprint `(tool_chain_hash + session_id)` and digest grouping/fingerprint (assert the digest fingerprint excludes the run date, so unchanged traces dedup across days) in `tests/unit/test_trace_alertable.py`

### Implementation for User Story 2

- [ ] T024 [US2] Implement `DangerousChain` (observed-in-production) → `AlertableFinding` mapping: tool sequence, matched-finding link, existing-issue link via marker search, session ID, trace source link, inherited severity, remediation from a covering `GuardrailPolicy`, in `ziran/application/trace_analysis/` (new mapping module) (depends on T003)
- [ ] T025 [US2] Implement `AnalyzerService.emit_findings(sinks, digest=False)` with per-`(chain, session)` and aggregated-digest modes in `ziran/application/trace_analysis/analyzer_service.py` (depends on T007, T024)
- [ ] T026 [US2] Extend the analyze config loader to parse the `alerts:` block (`!env`) in `ziran/application/trace_analysis/` config (depends on T005, T006)
- [ ] T027 [US2] Wire the `analyze-traces` CLI: `--alert` / `--digest` flags, build sinks via factory, map `AlertOutcome` to exit codes in `ziran/interfaces/cli/analyze_traces.py` (depends on T011, T025, T026)

**Checkpoint**: US1 and US2 both work independently.

---

## Phase 5: User Story 3 - Exported policies stay fresh automatically (Priority: P3)

**Goal**: A reusable composite GitHub Action re-scans, regenerates policies, and opens/updates a single refresh PR (or fails on diff). Independent of the sink work.

**Independent Test**: Run the action against the bundled example agent in a test repo → PR opened when committed bundle is stale, no PR when current.

### Tests for User Story 3

- [ ] T028 [US3] Self-test workflow `.github/workflows/policy-refresh-selftest.yml` that runs the action against the example agent and asserts PR-opened-when-stale / no-PR-when-current

### Implementation for User Story 3

- [ ] T029 [P] [US3] Author the composite action `.github/actions/export-policy/action.yml` (inputs: target, out-dir, target-formats, fail-on-diff, reviewer-team; steps: install → `ziran scan` → `ziran export-policy --formats` → diff → fixed-branch `ziran/policy-refresh` PR via `gh`, label `policy-refresh`, request reviewer) per contracts/cli_and_action.md
- [ ] T030 [P] [US3] Add the copyable workflow template `examples/07-cicd-quality-gate/policy-refresh.yml` (weekly schedule + `workflow_dispatch`), including a `concurrency: { group: ziran-policy-refresh, cancel-in-progress: true }` block so overlapping scheduled runs cannot open competing PRs (spec "Concurrent automation runs" edge case, FR-024)
- [ ] T031 [P] [US3] Verify `ziran export-policy` accepts a `--formats` scoping option; add it in `ziran/interfaces/cli/export_policy.py` if missing (FR-022)

**Checkpoint**: All three user stories independently functional.

---

## Phase 6: Polish & Cross-Cutting Concerns

- [ ] T032 [P] Add the "Alerting" section to `docs/guides/analyze-traces.md` (FR-026)
- [ ] T033 [P] Write the new guide `docs/guides/policy-refresh-automation.md` (FR-027)
- [ ] T034 Run quickstart.md validation end-to-end (config samples, exit codes)
- [ ] T035 Run quality gates: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`, `uv run pytest --cov=ziran` (≥85%)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: no dependencies.
- **Foundational (Phase 2)**: depends on Setup. BLOCKS US1 and US2.
- **US1 (Phase 3)** and **US2 (Phase 4)**: depend on Foundational. US2 reuses the GitHub sink but is independently testable.
- **US3 (Phase 5)**: depends only on Setup — can run fully in parallel with Foundational/US1/US2.
- **Polish (Phase 6)**: after the targeted stories are complete.

### User Story Dependencies

- US1 (P1): after Phase 2. No dependency on other stories.
- US2 (P2): after Phase 2. Reuses shared sinks; no hard dependency on US1.
- US3 (P3): after Phase 1. Independent of US1/US2.

### Within Each User Story

- Tests written first and expected to FAIL before implementation.
- Domain mapping (entities) → application service → CLI wiring.

### Parallel Opportunities

- Phase 1: T002 ∥ T001 setup steps.
- Phase 2: T003 ∥ T004 ∥ T005 ∥ T006 ∥ T008 (distinct files); then T007/T009/T010 (sinks/dispatcher); tests T012–T015 ∥.
- US1 tests T016 ∥ T017; US2 tests T022 ∥ T023.
- US3 (T028–T031) can be developed alongside Phase 2 by a second person.
- Polish T032 ∥ T033.

---

## Parallel Example: Foundational Phase

```bash
# Distinct files, no interdependencies — launch together:
Task: "Create alerting domain entities in ziran/domain/entities/alerting.py"
Task: "Define AlertSink ABC in ziran/domain/ports/alert_sink.py"
Task: "Implement !env YAML loader in ziran/infrastructure/config/env_yaml.py"
Task: "Implement AlertSinkConfig/AlertConfig in ziran/application/alerting/config.py"
Task: "Implement DryRunSink in ziran/infrastructure/alert_sinks/dry_run_sink.py"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Phase 1 Setup → 2. Phase 2 Foundational (CRITICAL) → 3. Phase 3 US1 → 4. STOP & validate `watch-registry` alerting independently → 5. Demo MVP.

### Incremental Delivery

Setup + Foundational → US1 (MVP, #272) → US2 (#274) → US3 (#273), each independently testable and shippable. US3 can land in parallel since it shares no code with the sinks.

### Parallel Team Strategy

After Foundational: Dev A → US1, Dev B → US2. Dev C can take US3 immediately after Setup (no Foundational dependency).

---

## Notes

- [P] = different files, no incomplete-task dependencies.
- The GitHub sink (T010) is the shared dedup-bearing adapter reused by both US1 and US2 — its idempotency test (T015) is foundational.
- Preserve the existing `watch-registry` severity-gate exit behavior; layer the delivery-failure exit (2) on top (research R3).
- Commit after each task or logical group; never leave CI red (per CLAUDE.md).
