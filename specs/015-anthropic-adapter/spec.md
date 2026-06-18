# Feature Specification: Anthropic SDK Native Adapter

**Feature Branch**: `015-anthropic-adapter`
**Created**: 2026-05-22
**Status**: Accepted
**Input**: "Add native Anthropic SDK adapter for direct Claude scanning without LangChain wrapping."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Scan a Claude agent directly (Priority: P1)

A security tester has a Claude-based agent built with the Anthropic SDK. They run `ziran scan --framework anthropic --agent-path ./my_claude_agent.py` to scan it directly, without needing LangChain as an intermediary.

**Why this priority**: Core value — enables scanning the most popular frontier model natively.

**Independent Test**: Create an AnthropicAdapter with a mocked client, invoke it, verify AgentResponse is returned.

**Acceptance Scenarios**:

1. **Given** an Anthropic client and model, **When** `invoke()` is called, **Then** the response is returned as a standardized `AgentResponse` with content and tool calls.
2. **Given** an Anthropic adapter with tools, **When** `discover_capabilities()` is called, **Then** all tool definitions are returned as `AgentCapability` objects.
3. **Given** a conversation, **When** `get_state()` is called, **Then** the conversation history is returned. **When** `reset_state()` is called, **Then** history is cleared.

### User Story 2 - CLI framework option (Priority: P1)

The `--framework anthropic` option appears in the `scan` and `discover` CLI commands.

**Acceptance Scenarios**:

1. **Given** the CLI, **When** `--framework anthropic` is used, **Then** the AnthropicAdapter is loaded.
2. **Given** the anthropic package is not installed, **When** the adapter is loaded, **Then** a clear error tells the user how to install it.

### Edge Cases

- Tool calls extracted from `tool_use` content blocks
- Sync client wrapped with `asyncio.to_thread`
- Token usage from Anthropic `usage` field

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Implement all `BaseAgentAdapter` abstract methods
- **FR-002**: Register `"anthropic"` in CLI `--framework` Choice
- **FR-003**: Add to adapter factory with lazy import
- **FR-004**: `anthropic` as optional dependency group in `pyproject.toml`
- **FR-005**: Extract tool calls from `tool_use` content blocks
- **FR-006**: Extract token usage from response `usage` field

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: `ziran scan --framework anthropic` loads successfully
- **SC-002**: All BaseAgentAdapter methods work with mocked client
- **SC-003**: All existing tests pass unchanged
