# Research: Split AgentScanner

## Decision 1: Module Boundary Strategy

**Decision**: Extract by responsibility, not by class hierarchy. Each module owns one concern.

**Rationale**: The current scanner mixes five concerns (orchestration, phase execution, attack execution, progress events, result building). Splitting by concern creates modules with high cohesion and minimal coupling.

**Alternatives considered**:
- Extract base classes → Rejected: adds inheritance complexity for no benefit
- Single "executors" module → Rejected: still too large, mixes phase and attack concerns

## Decision 2: Circular Import Prevention

**Decision**: Dependency direction is strictly: scanner → phase_executor → attack_executor. Progress and result_builder are leaf modules imported by any layer.

**Rationale**: scanner.py currently calls phase methods which call attack methods. Keeping this call direction as the import direction prevents cycles.

**Alternatives considered**:
- Callback-based decoupling → Rejected: over-engineering for an internal package
- Protocol classes for each module → Rejected: YAGNI per constitution

## Decision 3: Backward Compatibility via __init__.py

**Decision**: Re-export `ProgressEventType`, `ProgressEvent`, `AgentScannerError`, and `AgentScanner` from `__init__.py`. External code that imports from `ziran.application.agent_scanner` continues to work.

**Rationale**: The web UI and CLI both import these types. Changing import paths would be a breaking change.

**Alternatives considered**:
- Deprecation warnings on old imports → Rejected: unnecessary for internal refactor
- Move types to domain layer → Rejected: these are application-layer concerns

## Decision 4: Knowledge Graph Stays in Scanner

**Decision**: The `AttackKnowledgeGraph` management (`_update_graph_from_phase`, `_discover_and_map_capabilities`) remains in `scanner.py` as campaign-level orchestration logic.

**Rationale**: Graph updates depend on the full campaign context (all phases, all results). Extracting it would require passing the entire graph state through every layer, adding coupling rather than reducing it.

## Decision 5: Lazy Imports Follow Their Consumer

**Decision**: Each lazy import (`TacticExecutor`, `PromptEncoder`, `MCPMetadataAnalyzer`, `UtilityMeasurer`) moves to the module that actually uses it.

**Rationale**: Keeps each module self-contained. The lazy import pattern is preserved for optional dependencies.
