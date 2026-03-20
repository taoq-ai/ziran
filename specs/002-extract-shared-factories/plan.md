# Implementation Plan: Extract Shared Adapter & Strategy Factories

**Branch**: `002-extract-shared-factories` | **Date**: 2026-03-20 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/002-extract-shared-factories/spec.md`

## Summary

Extract adapter and strategy creation logic from CLI-private functions (`_load_remote_adapter`, `_load_agent_adapter`, `_build_strategy` and helpers) into `ziran/application/factories.py`. Replace `click.ClickException` with standard Python exceptions, remove Rich console output from factories. Update CLI to import from the new module and handle error conversion + display at the interface boundary.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix: 3.11, 3.12, 3.13)
**Primary Dependencies**: click (CLI only), PyYAML, Playwright (optional), boto3 (optional), LangChain (optional), CrewAI (optional)
**Storage**: N/A (no data persistence in this feature)
**Testing**: pytest with markers (@pytest.mark.unit, @pytest.mark.integration)
**Target Platform**: Linux/macOS/Windows (CLI tool + library)
**Project Type**: CLI tool / library (hexagonal architecture)
**Performance Goals**: N/A (pure refactor, no performance changes)
**Constraints**: mypy strict mode, ruff lint/format, 85%+ coverage
**Scale/Scope**: ~5 functions moved, ~2 files changed, ~1 new file, ~1 new test file

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Hexagonal Architecture | ✅ PASS | Factory moves FROM interfaces → TO application layer. Dependencies flow inward correctly. |
| II. Type Safety | ✅ PASS | All factory functions will have full type annotations. Return types use domain interfaces (BaseAgentAdapter, CampaignStrategy protocol). |
| III. Test Coverage | ✅ PASS | New unit tests for factories. Existing tests must keep passing. |
| IV. Async-First | ✅ PASS | Factories are sync (object creation). Adapters use async for I/O — unchanged. |
| V. Extensibility via Adapters | ✅ PASS | Factory pattern makes adapter creation more accessible to new interfaces. |
| VI. Simplicity | ✅ PASS | No new abstractions — just moving functions. No premature factory classes. |
| Quality Gates | ✅ PASS | ruff, mypy, pytest will be validated. |
| Conventional Commits | ✅ PASS | `refactor: extract shared adapter/strategy factories` |

**No violations. Gate passed.**

## Project Structure

### Documentation (this feature)

```text
specs/002-extract-shared-factories/
├── plan.md              # This file
├── research.md          # Phase 0 output — design decisions
├── data-model.md        # Phase 1 output — entity reference
├── quickstart.md        # Phase 1 output — usage guide
├── checklists/
│   └── requirements.md  # Spec quality checklist
└── tasks.md             # Phase 2 output (/speckit.tasks command)
```

### Source Code (repository root)

```text
ziran/
├── application/
│   ├── factories.py          # NEW — shared adapter + strategy factory functions
│   └── strategies/           # UNCHANGED — strategy implementations
│       ├── protocol.py
│       ├── fixed.py
│       ├── adaptive.py
│       └── llm_adaptive.py
├── domain/
│   ├── entities/
│   │   └── target.py         # UNCHANGED — TargetConfig, ProtocolType
│   └── interfaces/
│       └── adapter.py        # UNCHANGED — BaseAgentAdapter
├── infrastructure/
│   └── adapters/             # UNCHANGED — all adapter implementations
│       ├── http_adapter.py
│       ├── browser_adapter.py
│       ├── langchain_adapter.py
│       ├── crewai_adapter.py
│       ├── bedrock_adapter.py
│       └── agentcore_adapter.py
└── interfaces/
    └── cli/
        └── main.py           # MODIFIED — imports from factories, removes private functions

tests/
└── unit/
    └── application/
        └── test_factories.py # NEW — unit tests for factory functions
```

**Structure Decision**: Existing hexagonal layout preserved. Single new module `factories.py` in the application layer. No new packages or structural changes.

## Complexity Tracking

No violations — this section is intentionally empty.
