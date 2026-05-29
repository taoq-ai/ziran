# Data Model: Split AgentScanner

This is a pure refactor — no new entities are introduced. Existing entities are redistributed across modules.

## Entity Ownership After Refactor

| Entity | Current Location | New Location | Notes |
|--------|-----------------|--------------|-------|
| `AgentScanner` | scanner.py | scanner.py | Stays, delegates to sub-modules |
| `ProgressEventType` | scanner.py | progress.py | Re-exported from `__init__.py` |
| `ProgressEvent` | scanner.py | progress.py | Re-exported from `__init__.py` |
| `AgentScannerError` | scanner.py | scanner.py | Stays (campaign-level error) |
| `_is_error_response()` | scanner.py | attack_executor.py | Used during attack evaluation |

## New Classes (Internal)

| Class | Module | Purpose |
|-------|--------|---------|
| `ProgressEmitter` | progress.py | Wraps optional callback, provides typed emit methods |
| `PhaseExecutor` | phase_executor.py | Executes a single phase with bounded concurrency |
| `AttackExecutor` | attack_executor.py | Executes a single attack (render → encode → invoke → detect) |
| `ResultBuilder` | result_builder.py | Static methods to construct PhaseResult and CampaignResult |

## Dependency Graph

```
scanner.py
├── phase_executor.py
│   └── attack_executor.py
├── progress.py (leaf)
└── result_builder.py (leaf)
```
