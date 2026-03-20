# Feature Specification: Pre-compile Regex Patterns in Static Analysis

**Feature Branch**: `003-precompile-regex-patterns`
**Created**: 2026-03-20
**Status**: Active
**Input**: User description: "Pre-compile regex patterns in static analysis checks (issue #113). Currently, CheckDefinition patterns are recompiled from YAML-defined strings on every file analysis call. For large codebases this is wasteful. Fix: pre-compile patterns when CheckDefinition is loaded. No behavior change, purely a performance optimization."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Faster Static Analysis on Large Codebases (Priority: P1)

As a security engineer scanning a large codebase with hundreds of files, I need the static analyzer to avoid redundant work so that scans complete faster and I get results sooner.

**Why this priority**: This is the core value — eliminating thousands of redundant regex compilations per scan directly reduces wall-clock time for every user.

**Independent Test**: Run static analysis on a directory with 100+ files and verify that regex patterns are compiled only once regardless of how many files are analyzed.

**Acceptance Scenarios**:

1. **Given** a static analysis configuration with 10 checks totaling 30 patterns, **When** I analyze a directory containing 100 files, **Then** each regex pattern is compiled exactly once (not 100 times)
2. **Given** a custom configuration with additional patterns, **When** I load the config and run analysis, **Then** custom patterns are also pre-compiled and reused across files
3. **Given** a scan of any size, **When** I compare results before and after this change, **Then** the findings are identical (zero behavior change)

---

### User Story 2 - Existing Tests and Integrations Continue Working (Priority: P2)

As a developer maintaining the static analysis module, I need all existing tests to pass without modification after this optimization so that I can be confident the refactor introduced no regressions.

**Why this priority**: Correctness is a hard constraint — any behavior change means the optimization has failed.

**Independent Test**: Run the full test suite and verify all static analysis tests pass without assertion changes.

**Acceptance Scenarios**:

1. **Given** the existing test suite, **When** I run all static analysis tests after the change, **Then** all tests pass without modification to test assertions
2. **Given** a configuration loaded from a file, **When** I merge two configurations and run analysis, **Then** merged patterns are correctly compiled and produce identical results

---

### Edge Cases

- What happens when a pattern string is invalid regex? (Should fail at load time rather than at first file analysis)
- What happens when a check definition has zero patterns? (Should produce no findings, same as before)
- What happens with the input validation check patterns which are stored as plain strings, not pattern rule objects?
- How does pre-compilation interact with config merging (two configs merged should produce correctly compiled patterns)?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Regex patterns MUST be compiled once when check definitions are created or loaded, not on each file analysis call
- **FR-002**: Analysis results MUST be identical before and after this change for any given input
- **FR-003**: Invalid regex patterns MUST raise errors at configuration load time rather than during file analysis
- **FR-004**: The dangerous tool check patterns MUST also be pre-compiled, not just standard check definition patterns
- **FR-005**: The input validation check patterns MUST also be pre-compiled
- **FR-006**: Configuration merging MUST produce correctly compiled patterns in the merged result
- **FR-007**: All existing tests MUST pass without changes to test assertions

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Each regex pattern is compiled exactly once per configuration load, regardless of the number of files analyzed
- **SC-002**: All existing static analysis tests pass without modification
- **SC-003**: Scanning a 100-file codebase with 10 checks and 30 patterns performs no more than 30 regex compilations (down from 3,000)
- **SC-004**: All quality gates pass (formatting, linting, type checking, tests)

## Assumptions

- The performance improvement is proportional to the number of files scanned — single-file scans see negligible benefit, which is acceptable
- Pre-compilation happens eagerly (at config load time), not lazily (at first use), to surface invalid patterns early
- The input validation function's patterns should also be pre-compiled for consistency, even though they run once per file (not per line)
