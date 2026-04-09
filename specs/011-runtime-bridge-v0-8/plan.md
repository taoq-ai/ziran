# Implementation Plan: v0.8 — Runtime Bridge and Positioning

**Branch**: `011-runtime-bridge-v0-8` | **Date**: 2026-04-09 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/011-runtime-bridge-v0-8/spec.md`

## Summary

Add three new CLI commands (`export-policy`, `analyze-traces`, `watch-registry`), four CI platform templates, and a landscape documentation page to bridge Ziran's pre-deploy findings into the runtime governance ecosystem. The approach reuses the existing knowledge graph engine and pattern library — no new runtime dependencies on the scan hot path.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix: 3.11, 3.12, 3.13)
**Primary Dependencies**: click (CLI), httpx (async HTTP), pydantic (models), networkx (graph), pyyaml (config), rich (output), mdutils (reports). New optional: `langfuse` (trace pull).
**Storage**: Local JSON files for registry snapshots (`.ziran/snapshots/`); no database.
**Testing**: pytest with `@pytest.mark.unit` / `@pytest.mark.integration`; pytest-asyncio for async tests.
**Target Platform**: Linux/macOS CLI; CI environments (GitHub, GitLab, Jenkins, CircleCI, Azure).
**Project Type**: CLI tool + Python library
**Performance Goals**: Policy export < 1s for 100 findings; trace analysis < 30s for 10k spans.
**Constraints**: Zero new dependencies on the scan hot path. Langfuse SDK is optional (`extras = ["langfuse"]`).
**Scale/Scope**: Campaign results with up to 500 findings; traces with up to 50k spans per file.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Hexagonal Architecture | ✅ Pass | New code follows ports & adapters: domain ports for `PolicyRenderer`, `TraceIngestor`, `SnapshotStore`; infrastructure adapters implement them. CLI in interfaces layer. |
| II. Type Safety | ✅ Pass | All new models as Pydantic; all functions typed; mypy strict. |
| III. Test Coverage | ✅ Pass | Unit tests for each renderer/adapter; integration tests for CLI commands; synthetic fixtures. Coverage ≥ 85%. |
| IV. Async-First | ✅ Pass | Trace ingestion (Langfuse API, MCP manifest fetch) uses async/await + httpx. File I/O uses sync (acceptable per constitution — no I/O budget concern). |
| V. Extensibility via Adapters | ✅ Pass | New formats/trace sources added by implementing ports, not modifying core. Attack patterns stay YAML-driven. |
| VI. Simplicity | ✅ Pass | One renderer class per policy format (no shared abstract IR). Reuse existing `ToolChainAnalyzer` without modification. |

## Project Structure

### Documentation (this feature)

```text
specs/011-runtime-bridge-v0-8/
├── spec.md
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output
│   ├── cli-export-policy.md
│   ├── cli-analyze-traces.md
│   ├── cli-watch-registry.md
│   └── python-api.md
└── tasks.md             # Phase 2 output (/speckit.tasks)
```

### Source Code (repository root)

```text
ziran/
├── domain/
│   ├── entities/
│   │   ├── capability.py          # Extended: DangerousChain gets trace fields
│   │   ├── phase.py               # Extended: CampaignResult gets source discriminator
│   │   └── policy.py              # NEW: GuardrailPolicy, PolicyFormat enum
│   └── ports/
│       ├── policy_renderer.py     # NEW: PolicyRenderer ABC
│       ├── trace_ingestor.py      # NEW: TraceIngestor ABC
│       └── snapshot_store.py      # NEW: SnapshotStore ABC
├── application/
│   ├── policy_export/
│   │   ├── __init__.py
│   │   └── export_service.py      # NEW: orchestrates finding → policy rendering
│   ├── trace_analysis/
│   │   ├── __init__.py
│   │   └── analyzer_service.py    # NEW: orchestrates trace → graph → findings
│   └── registry_watch/
│       ├── __init__.py
│       ├── watcher_service.py     # NEW: orchestrates fetch → diff → findings
│       └── typosquat_detector.py  # NEW: Levenshtein + substitution patterns
├── infrastructure/
│   ├── policy_renderers/
│   │   ├── __init__.py
│   │   ├── rego_renderer.py       # NEW: OPA Rego output
│   │   ├── cedar_renderer.py      # NEW: AWS Cedar output
│   │   ├── colang_renderer.py     # NEW: NeMo Colang 2.0 output
│   │   └── invariant_renderer.py  # NEW: Invariant Labs DSL output
│   ├── trace_ingestors/
│   │   ├── __init__.py
│   │   ├── otel_ingestor.py       # NEW: OTel JSONL parsing
│   │   └── langfuse_ingestor.py   # NEW: Langfuse file + API
│   └── snapshot_stores/
│       ├── __init__.py
│       └── json_file_store.py     # NEW: local JSON snapshot storage
└── interfaces/
    └── cli/
        ├── export_policy.py       # NEW: click subcommand
        ├── analyze_traces.py      # NEW: click subcommand
        ├── watch_registry.py      # NEW: click subcommand
        └── main.py                # MODIFIED: register new subcommands

examples/
└── 07-cicd-quality-gate/
    ├── gitlab-ci.yml              # NEW
    ├── Jenkinsfile                 # NEW
    ├── circleci-config.yml        # NEW
    └── azure-pipelines.yml        # NEW

docs/
├── concepts/
│   └── agent-security-landscape.md  # NEW
└── guides/
    ├── export-policy.md             # NEW
    ├── analyze-traces.md            # NEW
    ├── watch-registry.md            # NEW
    └── ci-integrations.md           # NEW

tests/
├── unit/
│   ├── test_policy_export.py        # NEW: one test class per renderer
│   ├── test_trace_analysis.py       # NEW: OTel + Langfuse parsing + graph walk
│   ├── test_registry_watcher.py     # NEW: diff detection + typosquatting
│   └── test_typosquat_detector.py   # NEW: Levenshtein + substitution tests
├── integration/
│   ├── test_export_policy_cli.py    # NEW: CLI end-to-end
│   ├── test_analyze_traces_cli.py   # NEW: CLI end-to-end
│   └── test_watch_registry_cli.py   # NEW: CLI end-to-end
└── fixtures/
    ├── sample_otel_traces.jsonl     # NEW: synthetic OTel traces
    ├── sample_langfuse_traces.json  # NEW: synthetic Langfuse export
    ├── mcp_manifest_v1.json         # NEW: baseline MCP manifest
    ├── mcp_manifest_v2_drift.json   # NEW: drifted MCP manifest
    └── mcp_manifest_typosquat.json  # NEW: typosquatted manifest
```

**Structure Decision**: Single-project CLI structure, extending the existing hexagonal layout. All new code lives within the established `ziran/` package across the four architectural layers. No new top-level packages needed.

## Architecture

### Phase A — Policy Export (#253)

```
CampaignResult JSON
    │
    ▼
ExportService (application/)
    ├── Loads findings from campaign result
    ├── Filters by severity floor
    ├── For each finding: calls PolicyRenderer.render(finding)
    │       │
    │       ├── RegoRenderer → .rego file
    │       ├── CedarRenderer → .cedar file
    │       ├── ColangRenderer → .co file
    │       └── InvariantRenderer → .invariant file
    │
    └── Writes files to output directory with finding-ID headers
```

**Key Design Decisions**:
- `PolicyRenderer` is a domain port (ABC) with one method: `render(finding: DangerousChain) -> str`.
- Each renderer is an infrastructure adapter. Format selection via a registry dict: `{"rego": RegoRenderer, ...}`.
- The `ExportService` is an application-layer use case that accepts a `CampaignResult` and a target format, iterates findings, and delegates rendering.
- Findings whose tool-chain cannot be expressed in the target format are skipped with a logged reason (Cedar limitation for multi-step sequences).

### Phase B — Trace Analyzer (#254)

```
OTel JSONL / Langfuse export
    │
    ▼
TraceIngestor (infrastructure/)
    ├── OTelIngestor: parse JSONL → list[TraceSession]
    └── LangfuseIngestor: parse JSON or pull API → list[TraceSession]
    │
    ▼
AnalyzerService (application/)
    ├── For each TraceSession:
    │   ├── Build temporary AttackKnowledgeGraph with tool nodes + CAN_CHAIN_TO edges
    │   ├── Pass graph to existing ToolChainAnalyzer.analyze()
    │   └── Annotate DangerousChain results with trace metadata
    │
    └── Aggregate: deduplicate, count occurrences, compute first/last seen
    │
    ▼
Standard report pipeline (existing ReportGenerator)
    └── HTML/MD/JSON with "observed in production" badge
```

**Key Design Decisions**:
- `TraceIngestor` is a domain port: `async def ingest(source: Path | str) -> list[TraceSession]`.
- `TraceSession` is a new domain entity: `session_id`, `agent_name`, `tool_calls: list[ToolCallEvent]`, `start_time`, `end_time`.
- `ToolCallEvent`: `tool_name`, `arguments`, `result`, `timestamp`, `span_id`.
- The analyzer builds a temporary graph per session and runs the existing `ToolChainAnalyzer` — zero changes to the pattern engine.
- Langfuse SDK is an optional dependency under `extras = ["langfuse"]`. If not installed, the `--source langfuse --api` path raises a clear error.

### Phase C — Registry Watcher (#255)

```
registry.yaml (user config)
    │
    ▼
WatcherService (application/)
    ├── For each MCP server in config:
    │   ├── Fetch current manifest via MCP protocol handler
    │   ├── Load previous snapshot from SnapshotStore
    │   ├── Diff: added/removed tools, description changes, schema changes
    │   ├── Run TyposquatDetector against allowlist
    │   └── Emit findings via standard report formats
    │
    └── Update snapshot store with current manifest
```

**Key Design Decisions**:
- `SnapshotStore` is a domain port: `load(server_name) -> ManifestSnapshot | None`, `save(server_name, snapshot)`.
- `JsonFileStore` is the infrastructure adapter: writes to `.ziran/snapshots/{name}.json` with atomic rename.
- Diff logic lives in the application layer (pure function: `diff_manifests(old, new) -> list[DriftFinding]`).
- `TyposquatDetector` uses Levenshtein distance (stdlib or a small pure-Python implementation — no new dependency) + common substitution patterns. Threshold: distance ≤ 2.
- Network errors during manifest fetch do NOT corrupt the snapshot — the watcher logs a warning and skips the server, preserving the existing snapshot.

### Phase D — CI Templates (#256)

No new Python code. Four YAML/Groovy template files under `examples/07-cicd-quality-gate/` plus a docs page. Each template:
1. Installs Ziran via `pip install ziran`.
2. Runs `ziran ci --result-file <path> --severity-threshold <level> --coverage <level>`.
3. Uploads SARIF to the platform's native dashboard where supported.
4. Exits non-zero if severity gate fails.

A CI lint job in `.github/workflows/ci.yml` validates each template's syntax on every push.

### Phase E — Landscape Docs (#257)

No new Python code. Two documentation artifacts:
1. Updated README "Works With" section with runtime governance tools.
2. New `docs/concepts/agent-security-landscape.md` with Mermaid three-layer diagram, OWASP mapping, and cross-links to export-policy + analyze-traces docs.

## Implementation Phases

### Phase 1: Domain Foundation
- Extend `DangerousChain` with optional trace-evidence fields.
- Extend `CampaignResult` with `source` discriminator.
- Add new domain entities: `GuardrailPolicy`, `PolicyFormat`, `TraceSession`, `ToolCallEvent`, `ManifestSnapshot`, `RegistryConfig`, `DriftFinding`.
- Define domain ports: `PolicyRenderer`, `TraceIngestor`, `SnapshotStore`.
- **Gate**: mypy passes, existing tests green.

### Phase 2: Policy Export (#253)
- Implement four `PolicyRenderer` adapters (Rego, Cedar, Colang, Invariant).
- Implement `ExportService` application use case.
- Implement `export-policy` CLI subcommand.
- Add unit tests per renderer + integration test for CLI.
- Add docs page `guides/export-policy.md`.
- **Gate**: `ziran export-policy --result fixtures/sample.json --format rego --out /tmp/out` produces valid Rego.

### Phase 3: Trace Analyzer (#254)
- Implement `OTelIngestor` and `LangfuseIngestor` adapters.
- Implement `AnalyzerService` application use case (builds temp graph, runs `ToolChainAnalyzer`, annotates results).
- Implement `analyze-traces` CLI subcommand.
- Add synthetic trace fixtures (OTel JSONL + Langfuse JSON).
- Add unit tests for ingestors + analyzer + integration test for CLI.
- Add docs page `guides/analyze-traces.md`.
- **Gate**: `ziran analyze-traces --source otel --input fixtures/traces.jsonl` produces report with "observed in production" findings.

### Phase 4: Registry Watcher (#255)
- Implement `JsonFileStore` adapter.
- Implement `TyposquatDetector` (Levenshtein + substitution patterns).
- Implement `WatcherService` application use case.
- Implement `watch-registry` CLI subcommand.
- Add fixture manifests (baseline, drifted, typosquat).
- Add unit tests for diff logic + typosquatting + integration test for CLI.
- Add docs page `guides/watch-registry.md`.
- Add GitHub Action example under `examples/`.
- **Gate**: `ziran watch-registry --config fixtures/registry.yaml` detects drift in fixture manifests.

### Phase 5: CI Templates & Docs (#256, #257)
- Create four CI template files.
- Add CI lint job to validate templates.
- Create `guides/ci-integrations.md` docs page.
- Update README "Works With" section.
- Create `concepts/agent-security-landscape.md` with Mermaid diagram.
- **Gate**: CI lint passes; mkdocs build succeeds.

### Phase 6: Integration & Release
- End-to-end test: scan → export-policy → verify policy is valid.
- End-to-end test: analyze-traces → export-policy (the "full loop" from #254's docs).
- Cross-link landscape page to export-policy and analyze-traces.
- Quality gates: `ruff check .`, `ruff format --check .`, `mypy ziran/`, `pytest --cov=ziran` (≥ 85%).
- **Gate**: All quality gates pass; CI green.

## Complexity Tracking

No constitution violations. No complexity justifications needed.
