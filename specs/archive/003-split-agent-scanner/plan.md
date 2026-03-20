# Implementation Plan: Split AgentScanner into Focused Modules

**Branch**: `003-split-agent-scanner` | **Date**: 2026-03-20 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/003-split-agent-scanner/spec.md`

## Summary

Extract five responsibility areas from the 1159-line `scanner.py` into focused modules within the existing `agent_scanner/` package. The `AgentScanner` class remains the public entry point but delegates to `PhaseExecutor`, `AttackExecutor`, `ProgressEmitter`, and `ResultBuilder`. Zero behavior change. All existing tests must pass.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix: 3.11, 3.12, 3.13)
**Primary Dependencies**: asyncio, dataclasses, logging, OpenTelemetry (tracing)
**Storage**: N/A (in-memory knowledge graph via NetworkX)
**Testing**: pytest with `@pytest.mark.unit` markers
**Target Platform**: Linux/macOS (CLI tool)
**Project Type**: Library/CLI
**Performance Goals**: N/A (pure refactor, no performance changes)
**Constraints**: Zero behavior change, scanner.py under 300 lines, no module over 400 lines
**Scale/Scope**: 1 package (agent_scanner), ~1159 lines → ~5 files

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Gate | Status | Notes |
|------|--------|-------|
| Hexagonal Architecture | ✅ PASS | All new modules stay in `application/` layer. No new cross-layer dependencies. |
| Type Safety | ✅ PASS | All extracted functions retain existing type annotations. mypy strict enforced. |
| Test Coverage | ✅ PASS | Existing 541 scanner tests + new per-module unit tests. Coverage maintained. |
| Async-First | ✅ PASS | Async methods remain async. No sync conversions. |
| Extensibility via Adapters | ✅ PASS | No adapter changes. Sub-modules take adapters via constructor injection. |
| Simplicity | ✅ PASS | Pure decomposition — no new abstractions, no new dependencies. |
| Quality Gates | ✅ PASS | ruff, mypy, pytest all required to pass. |

## Project Structure

### Documentation (this feature)

```text
specs/003-split-agent-scanner/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
└── tasks.md             # Phase 2 output
```

### Source Code (repository root)

```text
ziran/application/agent_scanner/
├── __init__.py           # Re-exports: AgentScanner, ProgressEventType, ProgressEvent, AgentScannerError
├── scanner.py            # Campaign orchestrator (<300 lines) — uses PhaseExecutor, ResultBuilder
├── phase_executor.py     # Phase execution with semaphore-based concurrency
├── attack_executor.py    # Single attack execution: render, encode, invoke, detect
├── progress.py           # ProgressEventType, ProgressEvent, ProgressEmitter
└── result_builder.py     # PhaseResult and CampaignResult construction

tests/unit/application/
├── test_scanner.py                  # Existing (updated imports if needed)
├── test_phase_executor.py           # New: phase execution unit tests
├── test_attack_executor.py          # New: attack execution unit tests
├── test_progress_emitter.py         # New: progress emission unit tests
└── test_result_builder.py           # New: result construction unit tests
```

**Structure Decision**: All new modules stay within the existing `agent_scanner/` package. No new packages created. The `__init__.py` re-exports all public types for backward compatibility.

## Complexity Tracking

No constitution violations — no complexity justification needed.
