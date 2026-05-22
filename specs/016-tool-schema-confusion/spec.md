# Feature Specification: Tool-Schema Confusion Attack Vectors

**Feature Branch**: `016-tool-schema-confusion`
**Created**: 2026-05-22
**Status**: Draft
**Input**: "Add attack vectors for tool-schema confusion: type confusion, enum injection, schema override, missing required fields, extra field injection, nested payload smuggling."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - New attack category in vector library (Priority: P1)

A security tester runs a ZIRAN scan and the tool-schema confusion vectors test whether the agent validates tool parameters correctly. These vectors probe how agents handle malformed schemas, unexpected types, and schema manipulation.

**Why this priority**: New attack surface — tests a gap no competitor covers well.

**Independent Test**: `ziran library --category tool_manipulation` shows the new tool-schema confusion vectors.

**Acceptance Scenarios**:

1. **Given** the attack library, **When** vectors are loaded, **Then** tool-schema confusion vectors are available under `tool_manipulation` category.
2. **Given** the vectors, **When** each is parsed, **Then** it has valid prompts, success/failure indicators, OWASP mapping, and ATLAS mapping.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Add 8-12 attack vectors in a new YAML file `tool_schema_confusion.yaml`
- **FR-002**: Use existing `tool_manipulation` category (no new enum)
- **FR-003**: Each vector MUST have OWASP mapping (LLM07/LLM08) and ATLAS mapping
- **FR-004**: Vectors MUST include carefully crafted success/failure indicators
- **FR-005**: All vectors MUST load correctly via AttackLibrary

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: All vectors load without errors via AttackLibrary
- **SC-002**: `ziran library --category tool_manipulation` shows the new vectors
- **SC-003**: Vectors cover 6 distinct confusion attack sub-types
