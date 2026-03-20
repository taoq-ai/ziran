# Research: Extract Shared Adapter & Strategy Factories

**Feature**: 002-extract-shared-factories
**Date**: 2026-03-20

## R1: Where to Place the Factory Module

**Decision**: `ziran/application/factories.py`

**Rationale**: The application layer orchestrates domain entities and infrastructure adapters. Factory functions that wire together infrastructure implementations based on configuration belong here — they are "use case setup" logic. This follows hexagonal architecture: the application layer knows about both domain ports and infrastructure adapters.

**Alternatives considered**:
- `ziran/interfaces/shared.py` — Rejected: the `interfaces/` layer should only contain driving adapters (CLI, web). Shared logic between interfaces belongs in the application layer.
- `ziran/infrastructure/factories.py` — Rejected: factories orchestrate across multiple infrastructure adapters, which is application-layer responsibility.
- `ziran/application/factories/` (package) — Rejected for now: YAGNI. A single module is sufficient. Can be split later if it grows.

## R2: Error Handling — click.ClickException Dependency

**Decision**: Replace `click.ClickException` with framework-agnostic exceptions in the factory module. The CLI wraps these into `click.ClickException` at the call site.

**Rationale**: The factory module must not depend on `click` (an interface-layer concern). Using standard Python exceptions (or custom domain exceptions) keeps the module reusable by any interface.

**Pattern**:
- Factory raises `ValueError` for invalid input (unsupported framework, missing config)
- Factory raises `ImportError` for missing optional dependencies (with helpful install instructions in the message)
- Factory raises `FileNotFoundError` for missing files
- CLI catches these and wraps in `click.ClickException`

**Alternatives considered**:
- Custom exception hierarchy (`AdapterError`, `StrategyError`) — Rejected: YAGNI for a refactor. Standard exceptions are sufficient and the caller can always add specificity.
- Keeping `click.ClickException` in factories — Rejected: violates hexagonal architecture (application → interface dependency).

## R3: Console Output in _load_remote_adapter

**Decision**: Remove Rich console output (`console.print`) from the factory function. Move it to the CLI caller.

**Rationale**: The factory should be a pure creation function. Display logic belongs in the interface layer. The CLI caller can print target/protocol/auth info after receiving the adapter and config.

**Pattern**: The remote adapter factory returns both the adapter and the loaded config, so the CLI can display config details. Or, the CLI loads the config first and passes it to the factory.

## R4: _load_python_object Helper

**Decision**: Move `_load_python_object` into the factory module as a private helper. It has no CLI dependencies beyond `click.ClickException` (which will be replaced).

**Rationale**: This function is needed by the agent adapter factory to load Python objects from files. It's pure utility with no interface-layer semantics.

## R5: _load_bedrock_config Helper

**Decision**: Move `_load_bedrock_config` into the factory module as a private helper. Replace `click.ClickException` with standard exceptions.

**Rationale**: Same as R4 — pure configuration loading logic needed by the adapter factory.

## R6: _build_strategy Console Warning

**Decision**: The strategy factory should use Python `logging.warning()` instead of `console.print` for the LLM fallback warning. Alternatively, return the fallback info so the caller can display it.

**Rationale**: Logging is framework-agnostic. The CLI can configure a Rich logging handler; the web backend can log to its own system.

**Decision**: Use `logging.warning()` — it's the simplest approach and the project already uses the logging infrastructure.
