# Feature Specification: Configurable Detector Pipeline

**Feature Branch**: `feat/003-configurable-detector-pipeline`
**Created**: 2026-03-20
**Status**: Active
**Input**: User description: "Make detector pipeline configurable and extensible (issue #121)."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Disable Specific Detectors (Priority: P1)

As a security engineer running a targeted scan, I need to disable specific detectors (e.g., the LLM judge or authorization detector) so that I can control which detection methods are active for my specific use case.

**Why this priority**: This is the most requested capability — users need to customize which detectors run.

**Independent Test**: Create a pipeline with a specific detector disabled and verify it doesn't run.

**Acceptance Scenarios**:

1. **Given** a detector configuration that disables the side_effect detector, **When** I run a scan, **Then** the side_effect detector does not execute
2. **Given** a default configuration with no overrides, **When** I run a scan, **Then** all detectors run as before (backward compatible)

---

### User Story 2 - Register Custom Detectors (Priority: P2)

As a developer building a custom security tool, I need to register my own detector implementation so that I can extend the pipeline without modifying source code.

**Why this priority**: Extensibility is the second most important capability.

**Independent Test**: Register a custom detector and verify it runs during evaluation.

**Acceptance Scenarios**:

1. **Given** a custom detector implementing the BaseDetector interface, **When** I register it with the pipeline, **Then** it runs during evaluation and its results contribute to the verdict
2. **Given** a custom detector with a duplicate name, **When** I register it, **Then** it replaces the existing detector

---

### Edge Cases

- What happens when all detectors are disabled? (Should return conservative default: attack failed)
- What happens when a custom detector raises an exception? (Should be caught and logged, not crash the pipeline)

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Pipeline MUST accept an optional detector configuration that enables/disables detectors by name
- **FR-002**: Pipeline MUST provide a `register_detector()` method for adding custom detectors
- **FR-003**: Default behavior (no configuration) MUST be identical to current behavior
- **FR-004**: Custom detectors MUST participate in the resolution strategy
- **FR-005**: All existing tests MUST pass without modification

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Detectors can be individually disabled via configuration
- **SC-002**: Custom detectors can be registered and participate in verdicts
- **SC-003**: All existing tests pass without modification
- **SC-004**: All quality gates pass

## Assumptions

- The resolution strategy remains the same — only the set of active detectors changes
- Custom detectors participate in the "ambiguous → LLM judge" step but don't override the priority chain (refusal → side-effect → authorization → indicator → LLM judge)
- Configuration is a simple dict mapping detector names to enabled/disabled status
