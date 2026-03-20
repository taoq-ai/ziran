# Feature Specification: Extract Shared Adapter & Strategy Factories

**Feature Branch**: `002-extract-shared-factories`
**Created**: 2026-03-20
**Status**: Active
**Input**: Issue #89 — Extract shared adapter/strategy loading from CLI into reusable utilities

## User Scenarios & Testing *(mandatory)*

### User Story 1 - CLI Scan Works Identically After Refactor (Priority: P1)

A user runs `ziran scan` from the command line exactly as they do today. The CLI imports adapter and strategy creation from a shared factory module instead of private CLI functions. All existing scan configurations, target files, and adapter types continue to work identically.

**Why this priority**: This is the most critical story — the refactor must not break existing functionality for current users.

**Independent Test**: Can be fully tested by running the existing CLI test suite and manual `ziran scan` commands against all supported adapter types (HTTP, browser, LangChain, CrewAI, Bedrock, AgentCore).

**Acceptance Scenarios**:

1. **Given** a user with an existing HTTP target YAML, **When** they run `ziran scan --target target.yaml`, **Then** the scan completes with identical results as before the refactor
2. **Given** a user with a LangChain agent, **When** they run `ziran scan --framework langchain --agent-path my_agent.py:agent_executor`, **Then** the adapter loads and scan runs as before
3. **Given** a user specifying `--strategy adaptive`, **When** the scan runs, **Then** the AdaptiveStrategy is created and behaves identically

---

### User Story 2 - Web UI Backend Reuses Factories (Priority: P2)

A developer building the web UI backend imports the shared factory functions to create adapters and strategies without duplicating CLI logic. The factories are accessible as a clean public API from the application layer.

**Why this priority**: This is the primary motivation for the refactor — enabling code reuse between CLI and web UI interfaces.

**Independent Test**: Can be tested by importing the factory module from a separate Python script or test file and verifying adapter/strategy creation works without CLI dependencies.

**Acceptance Scenarios**:

1. **Given** a developer writing the web backend, **When** they import from the shared factory module, **Then** they can create an HTTP adapter from a target config without any CLI imports
2. **Given** a developer writing the web backend, **When** they call the strategy factory with a strategy name, **Then** they receive a properly configured strategy instance
3. **Given** a developer writing the web backend, **When** they call the agent adapter factory with framework name and path, **Then** they receive a working adapter without CLI dependencies

---

### User Story 3 - Future Interface Integration (Priority: P3)

A developer building any new interface (API server, SDK, notebook integration) can create adapters and strategies by importing from a single, well-documented factory module in the application layer.

**Why this priority**: Ensures the refactor follows hexagonal architecture principles so any future port/interface can reuse the same factories.

**Independent Test**: Can be tested by verifying the factory module has no imports from the `interfaces` layer, only from `domain` and `infrastructure`.

**Acceptance Scenarios**:

1. **Given** the factory module, **When** inspecting its imports, **Then** it depends only on domain entities and infrastructure adapters — not on any interface-layer code (CLI, web, etc.)

---

### Edge Cases

- What happens when an unsupported framework name is passed to the adapter factory? The factory should raise a clear, descriptive error.
- What happens when a target YAML file is malformed or missing? The factory should propagate the existing error behavior unchanged.
- What happens when `llm_client` is `None` but `llm-adaptive` strategy is requested? The factory should fall back to `AdaptiveStrategy` as the CLI does today.
- What happens when the Bedrock config is a bare agent ID string vs. a full YAML? The factory should handle both formats as the CLI does today.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST provide a shared factory function to create remote adapters (HTTP, browser) from a target configuration file path and optional protocol override
- **FR-002**: System MUST provide a shared factory function to create agent adapters (LangChain, CrewAI, Bedrock, AgentCore) from a framework name and agent path
- **FR-003**: System MUST provide a shared factory function to create campaign strategies (Fixed, Adaptive, LLM-Adaptive) from a strategy name, stop-on-critical flag, and optional LLM client
- **FR-004**: The CLI `scan` command MUST be updated to call the shared factories instead of private functions, with no behavior change
- **FR-005**: The shared factory module MUST reside in the application layer, with no dependencies on interface-layer code
- **FR-006**: The shared factories MUST preserve all existing error handling, fallback behavior, and edge case handling from the current CLI functions
- **FR-007**: All existing tests MUST continue to pass without modification (or with minimal import path updates)

### Key Entities

- **AdapterFactory**: Responsible for creating the appropriate agent adapter based on target configuration or framework specification
- **StrategyFactory**: Responsible for creating the appropriate campaign strategy based on name and configuration parameters

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: All existing CLI scan tests pass without behavioral changes
- **SC-002**: The shared factory module can be imported and used without any CLI or interface-layer dependencies
- **SC-003**: The CLI `scan` command contains zero adapter/strategy instantiation logic — all creation is delegated to the shared factories
- **SC-004**: Creating an adapter or strategy via the factory produces an identical object to what the CLI produced before the refactor
- **SC-005**: Code duplication for adapter/strategy creation is reduced to zero — a single source of truth exists in the factory module
