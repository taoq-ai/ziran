# Feature Specification: Performance Optimizations for YAML Parsing, Benchmarks, and Chain Analysis

**Feature Branch**: `006-perf-optimizations`
**Created**: 2026-03-22
**Status**: Draft
**Input**: User description: "Performance optimization release covering 4 GitHub issues: #211, #214, #215, #216. The goal is to significantly reduce library init time, benchmark execution time, and chain analysis time for large tool sets."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Faster Attack Library Initialization (Priority: P1)

As a security engineer running scans, I want the attack library to load quickly so that CLI commands and scan operations start without noticeable delay.

**Why this priority**: Library initialization is the single largest bottleneck — it blocks every scan, every CLI command, and every benchmark run. It is called dozens of times during benchmark generation, compounding the cost.

**Independent Test**: Can be tested by measuring library init time before and after the change, confirming a 5x+ speedup on YAML parsing.

**Acceptance Scenarios**:

1. **Given** the attack library uses the default vector directory, **When** the library is initialized, **Then** YAML parsing completes at least 5x faster than the current baseline.
2. **Given** the fast YAML parser extension is not available in the environment, **When** the library is initialized, **Then** it falls back to the standard parser without errors or data loss.

---

### User Story 2 - Cached Library Instances Eliminate Redundant Parsing (Priority: P1)

As a developer running benchmarks or generating reports, I want the system to reuse a previously loaded attack library instead of re-parsing all YAML files each time, so that multi-step operations complete in seconds rather than minutes.

**Why this priority**: Benchmark generation creates 7+ independent library instances, each re-parsing 24 YAML files from disk. Caching eliminates ~85% of redundant work across the pipeline.

**Independent Test**: Can be tested by running the full benchmark generation pipeline and confirming that only 1 full library parse occurs (excluding the init benchmark which must measure fresh parsing).

**Acceptance Scenarios**:

1. **Given** multiple benchmark operations need the attack library with default configuration, **When** they request the library, **Then** they receive the same cached instance without re-parsing YAML files.
2. **Given** a caller requests the attack library with custom configuration (e.g., custom vector directories), **When** they request the library, **Then** they receive a fresh instance with their custom configuration applied.
3. **Given** the library init benchmark explicitly measures fresh initialization, **When** it runs, **Then** it creates a new instance each time and does not use the cache.

---

### User Story 3 - Faster CI Benchmark Execution (Priority: P2)

As a CI pipeline operator, I want benchmark tests to complete faster so that CI feedback loops are shorter and runner costs are reduced.

**Why this priority**: The performance benchmark module is the slowest test in the suite, taking 5-10 minutes on CI runners due to redundant library inits and excessive iterations.

**Independent Test**: Can be tested by running the performance benchmark test module and measuring total execution time, confirming it completes in under 60 seconds on typical hardware.

**Acceptance Scenarios**:

1. **Given** the benchmark suite runs with reduced iterations, **When** performance metrics are collected, **Then** results remain statistically meaningful (warm-up run eliminates cold-start bias).
2. **Given** non-init benchmarks use the cached library, **When** the full benchmark generation pipeline runs, **Then** total execution time is reduced by at least 50% compared to the current baseline.

---

### User Story 4 - Scalable Chain Analysis for Large Tool Sets (Priority: P2)

As a security engineer scanning agents with many tools (50+), I want chain analysis to complete in a reasonable time so that large-scale scans remain practical.

**Why this priority**: The current quadratic algorithm becomes a bottleneck at 50+ tools, taking 30-60 seconds, and becomes impractical at 100+ tools. Pre-filtering and reachability checks reduce unnecessary graph traversals.

**Independent Test**: Can be tested by creating a knowledge graph with 50+ tool nodes and measuring chain analysis time, confirming it completes in under 10 seconds.

**Acceptance Scenarios**:

1. **Given** an agent with 50+ tools in the knowledge graph, **When** indirect chain analysis runs, **Then** it completes in under 10 seconds.
2. **Given** tool pairs that cannot match any dangerous chain pattern, **When** the analyzer evaluates them, **Then** they are skipped without performing expensive graph path searches.
3. **Given** tool pairs where no graph path exists between them, **When** the analyzer evaluates them, **Then** the expensive all-paths search is skipped via a fast reachability check.
4. **Given** any optimization is applied, **When** chain analysis completes, **Then** the results are identical to the unoptimized version (no correctness regression).

---

### Edge Cases

- What happens when the YAML C extension (CSafeLoader) is not installed? The system must fall back to the pure-Python parser transparently.
- What happens when the cached library singleton is accessed from multiple threads? The singleton is acceptable for the current single-threaded usage; thread safety is out of scope.
- What happens when benchmark iterations are reduced to 1? The warm-up run still provides cold-start elimination; a single measured iteration is sufficient for regression detection with generous thresholds.
- What happens when the knowledge graph has 0 or 1 tool nodes? Chain analysis should return empty results without errors.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST use the fastest available YAML parser with automatic fallback to the standard parser when the fast parser is not available.
- **FR-002**: System MUST provide a factory function that returns a cached library instance for default configurations and a fresh instance for custom configurations.
- **FR-003**: All benchmark and report-generation callers that use default library configuration MUST use the cached factory function instead of direct instantiation.
- **FR-004**: The library initialization benchmark MUST continue to measure fresh instantiation time (not use the cache).
- **FR-005**: Benchmark measurement iterations MUST be reduced from 3 to 1 while retaining the warm-up run for cold-start elimination.
- **FR-006**: The chain analyzer MUST pre-filter tool pairs to skip those that cannot match any dangerous chain pattern before performing graph traversals.
- **FR-007**: The chain analyzer MUST perform a fast reachability check before invoking expensive all-paths graph searches.
- **FR-008**: All optimizations MUST preserve existing behavior — no changes to scan results, benchmark outputs, or chain analysis findings.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Attack library YAML parsing completes at least 5x faster than the current baseline.
- **SC-002**: Full benchmark generation pipeline creates at most 2 library instances (1 cached + 1 for init benchmark) instead of the current 7+.
- **SC-003**: Performance benchmark test module completes in under 60 seconds on typical hardware (down from 5-10 minutes on CI).
- **SC-004**: Chain analysis on a 50-tool knowledge graph completes in under 10 seconds.
- **SC-005**: All existing tests pass without modification (no correctness regressions).
