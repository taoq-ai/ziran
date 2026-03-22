# Feature Specification: Resilience Gap Metric

**Feature Branch**: `feat/155-resilience-gap-metric`
**Created**: 2026-03-20
**Status**: Draft
**Input**: Issue #155: Implement resilience gap metric (baseline vs under-attack delta)

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Measure Resilience Gap Delta (Priority: P1)

A security engineer runs a ZIRAN scan against an AI agent and receives a resilience gap metric showing the difference between baseline performance (agent operating normally) and under-attack performance (agent under active attack campaign). This delta quantifies how much the agent's task completion degrades when adversarial attacks are applied.

**Why this priority**: Core deliverable of the issue. Without the gap delta calculation, none of the reporting or benchmark integration matters.

**Independent Test**: Can be tested by running a scan and verifying the output includes baseline_performance, under_attack_performance, and resilience_gap fields with correct values.

**Acceptance Scenarios**:

1. **Given** a completed campaign with attack results and phase data, **When** resilience metrics are computed, **Then** the output includes baseline_performance, under_attack_performance, and resilience_gap values between 0 and 1.
2. **Given** a campaign where the agent resists all attacks, **When** resilience metrics are computed, **Then** the resilience_gap is 0 (no degradation).
3. **Given** a campaign where the agent fails every attack, **When** resilience metrics are computed, **Then** the resilience_gap reflects maximum degradation.

---

### User Story 2 - View Resilience Gap in Reports (Priority: P2)

After a scan completes, the security engineer sees the resilience gap metric in the scan report output, including the CLI summary and any generated report files. The metric is presented alongside the existing resilience score.

**Why this priority**: Reporting surfaces the metric to users. Without visibility, the computation has no practical value.

**Independent Test**: Can be tested by running a scan and checking the report output for resilience gap fields.

**Acceptance Scenarios**:

1. **Given** a completed scan with resilience metrics, **When** the report is generated, **Then** baseline performance, under-attack performance, and resilience gap are displayed.
2. **Given** a scan where no attacks were executed, **When** the report is generated, **Then** resilience gap fields show default values (no gap).

---

### User Story 3 - Track Resilience Gap in Benchmarks (Priority: P3)

The benchmark system tracks the resilience gap metric and reports it alongside other AILuminate-aligned metrics. GAP-09 is closed once implementation is complete.

**Why this priority**: Benchmark integration validates that the metric aligns with AILuminate expectations and closes the tracking gap.

**Independent Test**: Can be tested by running `generate_all.py` and verifying benchmark output includes resilience gap metrics and GAP-09 is marked closed.

**Acceptance Scenarios**:

1. **Given** the benchmark comparison is generated, **When** AILuminate metrics are computed, **Then** the resilience gap delta is included in the output.
2. **Given** the implementation is complete, **When** gap_status.py is run, **Then** GAP-09 shows status "closed".

---

### Edge Cases

- What happens when a campaign has zero attacks? Resilience gap should be 0 (no degradation measured).
- What happens when all phases succeed with full trust? Baseline should be 1.0, under-attack depends on attack results.
- What happens when there is only one phase? Trust degradation component uses 0.0 as default.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST compute a baseline_performance metric representing expected agent performance without attacks (derived from initial trust and phase success).
- **FR-002**: System MUST compute an under_attack_performance metric representing agent performance during an active attack campaign.
- **FR-003**: System MUST calculate resilience_gap as the delta between baseline and under-attack performance (baseline - under_attack), clamped to [0, 1].
- **FR-004**: System MUST include resilience gap fields in the ResilienceMetrics output model.
- **FR-005**: System MUST display resilience gap metrics in scan reports (CLI summary and generated reports).
- **FR-006**: System MUST include resilience gap in benchmark comparison output for AILuminate alignment.
- **FR-007**: System MUST update GAP-09 status to "closed" in gap tracking.

### Key Entities

- **ResilienceMetrics**: Extended with baseline_performance, under_attack_performance, and resilience_gap fields. Baseline derives from initial trust scores and phase success rates. Under-attack derives from post-campaign metrics.
- **Resilience Gap**: A 0-1 float where 0 = no degradation (agent fully resilient) and values approaching 1 = severe degradation.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Every completed scan produces resilience gap metrics (baseline, under-attack, delta) in its output.
- **SC-002**: Resilience gap values are always within the valid range [0, 1].
- **SC-003**: Benchmark output includes resilience gap delta metric aligned with AILuminate expectations.
- **SC-004**: GAP-09 is closed in benchmark tracking.
- **SC-005**: All existing tests continue to pass (no regressions).

## Assumptions

- Baseline performance is derived from initial trust score and phase completion data (no separate "clean run" required).
- Under-attack performance uses the same formula applied to post-campaign data.
- The resilience gap formula is: baseline_performance - under_attack_performance, representing how much capability the agent loses under attack.
