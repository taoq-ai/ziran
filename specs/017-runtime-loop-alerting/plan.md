# Implementation Plan: Runtime Loop Alerting and Automation

**Branch**: `017-runtime-loop-alerting` | **Date**: 2026-05-29 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/017-runtime-loop-alerting/spec.md`

## Summary

Close the v0.8 runtime-bridge feedback loop by adding a single shared notification capability — an `AlertSink` port with Slack-webhook and GitHub-issue adapters — and wiring it into the existing `watch-registry` (`watch()`) and `analyze-traces` (`AnalyzerService`) flows, plus a reusable composite GitHub Action that auto-refreshes exported policy bundles. Deduplication is stateless: a fingerprint marker is embedded in each GitHub issue body and rediscovered via the GitHub search API, so re-runs never open duplicates and no local dedup state is kept. The work is sliced into three independently shippable user stories (P1 registry alerting, P2 trace alerting, P3 policy-refresh automation).

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix: 3.11, 3.12, 3.13)
**Primary Dependencies**: httpx (async HTTP — Slack + GitHub REST), Pydantic v2 (config + entity models), PyYAML (config + new `!env` tag), Click (CLI). Composite GitHub Action uses `gh` CLI + bash, no new runtime deps.
**Storage**: None new. Dedup is stateless via GitHub-side issue markers; existing registry snapshots stay in `.ziran/snapshots/` (local JSON).
**Testing**: pytest with `@pytest.mark.unit` / `@pytest.mark.integration`; new dev dependency **respx** to mock httpx requests and assert request shape for both sinks (no real server, httpx-native). Action validated by a workflow under `.github/workflows/`.
**Target Platform**: Linux/macOS CLI; GitHub Actions Ubuntu runner for the composite action.
**Project Type**: Single-project hexagonal CLI (`ziran/` package).
**Performance Goals**: Not latency-sensitive; sinks fan out concurrently via `asyncio.gather` so total alert time ≈ slowest single sink, not the sum.
**Constraints**: No secrets in committed config (env-only, incl. `!env VAR_NAME`); dry-run contacts zero external services; partial-delivery failures exit with a distinct non-zero code separate from fatal errors.
**Scale/Scope**: Tens of findings per run; GitHub search-API dedup is one query per finding (acceptable at this volume).

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|---|---|---|
| I. Hexagonal Architecture | PASS | New `AlertSink` ABC in `domain/ports/alert_sink.py`; Slack + GitHub adapters in `infrastructure/alert_sinks/`. Application services (`watch()`, `AnalyzerService`) depend only on the port. Domain stays dependency-free. |
| II. Type Safety | PASS | All new code fully annotated; `AlertSink` is an ABC; findings and sink config are Pydantic models. mypy strict must stay green. |
| III. Test Coverage | PASS | Unit tests for fingerprinting, severity-floor filtering, dry-run, digest grouping; integration tests with respx asserting Slack + GitHub request shape and dedup idempotency. Target ≥85%. |
| IV. Async-First | PASS | `AlertSink.emit` is `async`; sinks use `httpx.AsyncClient`; fan-out via `asyncio.gather`. Sync only at the Click entry points (existing pattern). |
| V. Extensibility via Adapters | PASS | New sinks are added by implementing `AlertSink`; no core changes needed. Matches existing port/adapter style (`PolicyRenderer`, `TraceIngestor`). |
| VI. Simplicity | PASS (1 justified dep) | One shared port reused by two services (no duplication). One new **dev** dependency, respx — justified below. No new runtime deps; the Action reuses the `gh` CLI already present on runners. |

**New dependency justification (respx)**: The spec requires "integration tests with a mock HTTP server verifying request shape for both sinks." respx intercepts httpx at the transport layer, letting tests assert exact request URL/headers/body without standing up a real server — lighter and more precise than pytest-httpserver, and httpx-native (matches the project's HTTP convention). Dev-only; no runtime impact.

No violations requiring Complexity Tracking.

## Project Structure

### Documentation (this feature)

```text
specs/017-runtime-loop-alerting/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output (port + sink + action contracts)
└── tasks.md             # Phase 2 output (/speckit.tasks — not created here)
```

### Source Code (repository root)

```text
ziran/
├── domain/
│   ├── ports/
│   │   └── alert_sink.py            # NEW: AlertSink(ABC) — async emit(finding) -> DeliveryResult
│   └── entities/
│       ├── alerting.py              # NEW: AlertableFinding, DeliveryResult, AlertOutcome, fingerprint helpers
│       └── registry.py              # EXTEND: DriftFinding gains fingerprint()/to_alertable()
├── application/
│   ├── registry_watch/
│   │   └── watcher_service.py       # EXTEND: watch(..., alert_sinks, dry_run_alerts)
│   ├── trace_analysis/
│   │   └── analyzer_service.py      # EXTEND: AnalyzerService.emit_findings(sinks, digest=...)
│   └── alerting/
│       ├── __init__.py
│       ├── dispatch.py              # NEW: fan-out (asyncio.gather), severity-floor filter, dry-run, partial-failure aggregation
│       └── config.py                # NEW: AlertConfig / AlertSinkConfig Pydantic models
├── infrastructure/
│   ├── alert_sinks/
│   │   ├── __init__.py
│   │   ├── slack_sink.py            # NEW: SlackWebhookSink (httpx)
│   │   ├── github_issue_sink.py     # NEW: GitHubIssueSink (httpx REST, marker-based dedup)
│   │   └── dry_run_sink.py          # NEW: decorator/wrapper printing intended payload
│   └── config/
│       └── env_yaml.py              # NEW: `!env VAR_NAME` YAML loader/constructor
└── interfaces/cli/
    ├── watch_registry.py            # EXTEND: build sinks from config, --dry-run-alerts, exit-code contract
    └── analyze_traces.py            # EXTEND: --alert / --digest flags, exit-code contract

.github/actions/export-policy/
└── action.yml                       # NEW: composite action (gh CLI + python entry calling ziran)
.github/workflows/
└── policy-refresh-selftest.yml      # NEW: e2e test running the action against the example agent
examples/07-cicd-quality-gate/
└── policy-refresh.yml               # NEW: copyable workflow template
docs/guides/
├── analyze-traces.md                # EXTEND: "Alerting" section
└── policy-refresh-automation.md     # NEW guide

tests/
├── unit/
│   ├── test_alert_fingerprint.py
│   ├── test_alert_dispatch.py       # severity floor, dry-run, partial-failure aggregation/exit
│   └── test_env_yaml.py
└── integration/
    ├── test_slack_sink.py           # respx: request shape
    ├── test_github_issue_sink.py    # respx: create + marker-search dedup idempotency
    ├── test_watch_registry_alerting.py
    └── test_analyze_traces_alerting.py
```

**Structure Decision**: Single-project hexagonal layout (the only structure in this repo). The shared notification logic is split across the three layers: the contract (`domain/ports/alert_sink.py`) and finding shape (`domain/entities/alerting.py`) in the domain; orchestration (fan-out, filtering, dry-run, failure aggregation) in a new `application/alerting/` package reused by both services; concrete Slack/GitHub adapters and the `!env` YAML loader in infrastructure. The policy-refresh automation is repository tooling (a composite Action + workflow template) that invokes the existing `ziran scan` / `ziran export-policy` commands rather than new library code.

## Complexity Tracking

> No constitution violations. Section intentionally empty.
