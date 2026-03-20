# Feature Specification: Add MCP and Multi-Agent Delegation Patterns

**Feature Branch**: `feat/003-mcp-delegation-patterns`
**Created**: 2026-03-20
**Status**: Active
**Input**: User description: "Add MCP and multi-agent delegation patterns to tool classifier and chain analyzer (issue #163)."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Detect MCP Write and Git Operations (Priority: P1)

As a security engineer scanning an agent with MCP tools, I need the tool classifier to correctly identify MCP write operations as critical risk and MCP git operations at the appropriate risk level, so that dangerous MCP tools are flagged in scan reports.

**Why this priority**: MCP write operations (mcp_write_file) can modify the filesystem and should be classified as critical risk, matching the existing classification of write_file.

**Independent Test**: Classify MCP tool names and verify correct risk levels.

**Acceptance Scenarios**:

1. **Given** a tool named `mcp_write_file`, **When** classified, **Then** it is rated critical risk
2. **Given** a tool named `mcp_git_diff`, **When** classified, **Then** it is rated medium risk
3. **Given** a tool named `send_task`, **When** classified, **Then** it is rated high risk (A2A delegation)
4. **Given** tools named `payment` or `transaction`, **When** classified, **Then** they are rated critical risk

---

### User Story 2 - Detect MCP-Specific Exfiltration Chains (Priority: P2)

As a security engineer, I need the chain analyzer to detect MCP-specific exfiltration patterns (e.g., mcp_read_file → mcp_fetch) so that data exfiltration through MCP tool combinations is flagged.

**Why this priority**: Exfiltration through MCP tool chains is a documented attack vector (CVE-2025-53109 and related).

**Independent Test**: Create a tool graph with MCP read and fetch tools, run chain analysis, verify the exfiltration chain is detected.

**Acceptance Scenarios**:

1. **Given** tools `mcp_read_file` and `mcp_fetch` in a graph, **When** chain analysis runs, **Then** it detects a data_exfiltration chain
2. **Given** tools `mcp_git_diff` and `mcp_fetch` in a graph, **When** chain analysis runs, **Then** it detects a code exfiltration chain

---

### Edge Cases

- What happens when `mcp_write` matches but `mcp_write_file` also has a specific pattern? (More specific pattern should win via first-match ordering)
- How does `send_task` interact with existing `delegate_task` patterns?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Tool classifier MUST classify `mcp_write_file` and `mcp_write` as critical risk
- **FR-002**: Tool classifier MUST classify `mcp_git_diff` as medium risk
- **FR-003**: Tool classifier MUST classify `payment` and `transaction` broadly as critical risk
- **FR-004**: Tool classifier MUST classify `send_task` as high risk (A2A protocol)
- **FR-005**: Chain patterns MUST include `mcp_read_file → mcp_fetch` as data exfiltration
- **FR-006**: Chain patterns MUST include `mcp_git_diff → mcp_fetch` as code exfiltration
- **FR-007**: All existing tests MUST pass without modification

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: All new tool names are classified at the correct risk tier
- **SC-002**: New chain patterns are detected during graph analysis
- **SC-003**: All existing tests pass, all quality gates pass
- **SC-004**: Ground truth benchmark reflects improved coverage

## Assumptions

- New patterns are additive — no existing patterns are changed or removed
- MCP write operations carry the same risk as regular file write operations
- The A2A `send_task` pattern follows Google's A2A protocol naming convention
