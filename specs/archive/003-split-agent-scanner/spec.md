# Feature Specification: Split AgentScanner into Focused Modules

**Feature Branch**: `003-split-agent-scanner`
**Created**: 2026-03-20
**Status**: Active
**Input**: User description: "Refactor AgentScanner (issue #122): Split the 1159-line scanner.py into focused modules."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Scan Campaigns Produce Identical Results (Priority: P1)

As a security engineer running scan campaigns, I need the scanner to produce identical results after the refactor so that my existing workflows, integrations, and comparison baselines remain valid.

**Why this priority**: This is the core contract — zero behavior change is the entire point of a refactor. If results change, the refactor has failed.

**Independent Test**: Run the full existing test suite (1670 tests) and verify all pass. Run a scan campaign against a known target and compare output JSON to pre-refactor output.

**Acceptance Scenarios**:

1. **Given** a target YAML config and attack library, **When** I run `ziran scan --target target.yaml`, **Then** the campaign result (JSON report) is byte-identical to the pre-refactor output
2. **Given** an existing test suite with 541 scanner-specific tests, **When** I run the test suite after the refactor, **Then** all tests pass without modification to test assertions
3. **Given** a campaign with progress callbacks, **When** I run a scan with `on_progress` enabled, **Then** the same progress events fire in the same order with the same data

---

### User Story 2 - Components Are Independently Testable (Priority: P2)

As a developer adding new attack execution features, I need to test the attack executor in isolation without setting up a full campaign, so I can iterate faster and write focused unit tests.

**Why this priority**: Independent testability is the primary motivation for the decomposition. Each module should be instantiable and testable without the others.

**Independent Test**: Write a unit test that imports only `attack_executor` and exercises a single attack execution with a mock adapter, verifying the result without any campaign or phase context.

**Acceptance Scenarios**:

1. **Given** the attack executor module, **When** I instantiate it with a mock adapter and detector pipeline, **Then** I can execute a single attack and receive an `AttackResult` without involving the campaign orchestrator
2. **Given** the phase executor module, **When** I instantiate it with a mock attack executor and strategy, **Then** I can execute a phase with concurrent attacks without involving the campaign orchestrator
3. **Given** the result builder module, **When** I provide phase results and graph state, **Then** I can construct a `CampaignResult` without running any actual attacks
4. **Given** the progress module, **When** I instantiate it with a callback, **Then** I can emit progress events without any scanner dependency

---

### User Story 3 - Scanner File Is Under 300 Lines (Priority: P3)

As a maintainer reviewing pull requests, I need the main scanner file to be concise (under 300 lines) so I can quickly understand the campaign orchestration flow without wading through unrelated implementation details.

**Why this priority**: Code readability and maintainability is important but secondary to correctness and testability.

**Independent Test**: Count the lines in `scanner.py` after refactor. Verify it contains only campaign orchestration logic (phase loop, strategy integration, result assembly) and delegates everything else to sub-modules.

**Acceptance Scenarios**:

1. **Given** the refactored scanner.py, **When** I count its lines, **Then** it has fewer than 300 lines of code
2. **Given** the refactored scanner.py, **When** I inspect its imports, **Then** it imports from the new sub-modules (`phase_executor`, `attack_executor`, `progress`, `result_builder`) rather than implementing their logic inline

---

### Edge Cases

- What happens when a sub-module import fails (e.g., circular import between executor and scanner)?
- How does the refactor handle the lazy imports currently scattered throughout scanner.py (e.g., `TacticExecutor`, `PromptEncoder`, `MCPMetadataAnalyzer`)?
- What happens to the `_is_error_response` module-level helper function?
- How are the `ProgressEventType` and `ProgressEvent` dataclasses relocated without breaking external consumers (e.g., CLI, web UI)?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The refactored modules MUST produce identical `CampaignResult` output for any given input configuration
- **FR-002**: Each extracted module MUST be importable and instantiable independently without importing the scanner
- **FR-003**: The public API of `AgentScanner` (constructor signature, `run_campaign` method signature and return type) MUST remain unchanged
- **FR-004**: The `ProgressEventType` and `ProgressEvent` types MUST remain importable from their original location via re-exports in `__init__.py`
- **FR-005**: All existing tests (1670 total, 541 scanner-specific) MUST pass without changes to test assertions
- **FR-006**: The scanner.py file MUST contain fewer than 300 lines after refactor
- **FR-007**: Concurrent attack execution semantics (semaphore-based bounded concurrency) MUST be preserved exactly
- **FR-008**: OpenTelemetry tracing spans MUST continue to be emitted for campaign, phase, and attack operations
- **FR-009**: Token accounting MUST aggregate identically across phases and the final campaign result
- **FR-010**: The `AgentScannerError` exception MUST remain importable from its original location

### Key Entities

- **AgentScanner**: Campaign orchestrator — delegates to phase executor, assembles final result
- **PhaseExecutor**: Manages concurrent attack execution within a single phase, handles timeouts
- **AttackExecutor**: Executes a single attack (prompt rendering, encoding, adapter invocation, detection)
- **ProgressEmitter**: Encapsulates progress event emission logic with typed events
- **ResultBuilder**: Constructs `PhaseResult` and `CampaignResult` from raw execution data

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: All 1670 existing tests pass after refactor with zero test assertion changes
- **SC-002**: Scanner.py is under 300 lines (down from 1159)
- **SC-003**: Each new module (phase_executor, attack_executor, progress, result_builder) has at least 3 dedicated unit tests
- **SC-004**: No module in the agent_scanner package exceeds 400 lines
- **SC-005**: All quality gates pass: ruff check, ruff format, mypy, pytest

## Assumptions

- The `ProgressEventType`, `ProgressEvent`, and `AgentScannerError` types will be moved to their own modules but re-exported from `__init__.py` for backward compatibility
- Lazy imports (TacticExecutor, PromptEncoder, etc.) will move to the module that uses them
- The knowledge graph integration stays in the scanner (campaign-level concern) rather than being extracted
- The `_is_error_response` helper moves to `attack_executor.py` since it's used during attack evaluation
