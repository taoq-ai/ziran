# Feature Specification: Expand Ground Truth Dataset and Business Impact Categorization

**Feature Branch**: `007-ground-truth-business-impact`
**Created**: 2026-03-22
**Status**: Draft
**Input**: User description: "Expand ground truth benchmark dataset (#164) and add business impact categorization (#38)."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Authorization Detector Ground Truth Scenarios (Priority: P1)

As a benchmark maintainer, I want ground truth scenarios that exercise the authorization detector (BOLA/BFLA) so that I can measure its precision and recall against known vulnerable and safe configurations.

**Why this priority**: The authorization detector currently has zero test scenarios in the ground truth dataset. Without them, there is no way to validate that the detector correctly identifies broken authorization patterns or avoids false positives.

**Independent Test**: Can be tested by running the accuracy benchmark and confirming the authorization detector appears in results with measurable precision and recall scores.

**Acceptance Scenarios**:

1. **Given** a multi-tenant SaaS agent archetype with no authorization checks, **When** a BOLA attack is executed (cross-account data access), **Then** the authorization detector fires with a score above 0.7.
2. **Given** a multi-tenant SaaS agent archetype with no authorization checks, **When** a BFLA attack is executed (regular user invokes admin-only tool), **Then** the authorization detector fires with a score above 0.7.
3. **Given** a multi-tenant SaaS agent with per-request authorization validation, **When** a cross-account access attempt is made, **Then** the authorization detector does not fire (true negative).
4. **Given** at least 4 true-positive and 2 true-negative authorization scenarios exist, **When** the accuracy benchmark runs, **Then** precision and recall metrics are computed for the authorization detector.

---

### User Story 2 - LLM Judge Detector Ground Truth Scenarios (Priority: P1)

As a benchmark maintainer, I want ground truth scenarios designed for subtle and ambiguous attacks so that I can evaluate the LLM judge detector's added value over rule-based detectors.

**Why this priority**: The LLM judge detector handles edge cases where rule-based detectors are ambiguous. Without purpose-built scenarios, there is no way to measure whether the LLM judge correctly identifies subtle attacks that other detectors miss.

**Independent Test**: Can be tested by running the accuracy benchmark and confirming the LLM judge detector appears with measurable scores for scenarios where rule-based detectors are expected to be uncertain.

**Acceptance Scenarios**:

1. **Given** a scenario with subtle data exfiltration (encoded PII in a seemingly innocent response), **When** the detection pipeline runs, **Then** the LLM judge detector fires while rule-based indicator detectors do not.
2. **Given** a scenario with gradual trust escalation across a multi-turn conversation, **When** the detection pipeline evaluates the final response, **Then** the LLM judge assigns a high attack success score.
3. **Given** a scenario with a benign multi-turn conversation that superficially resembles escalation, **When** the detection pipeline evaluates it, **Then** the LLM judge correctly identifies it as a true negative.
4. **Given** at least 3 true-positive and 2 true-negative LLM judge scenarios exist, **When** the accuracy benchmark runs, **Then** precision and recall metrics are computed for the LLM judge detector.

---

### User Story 3 - Bedrock and AgentCore Agent Archetypes (Priority: P2)

As a benchmark maintainer, I want test agent archetypes for Bedrock and AgentCore frameworks so that framework-specific detection gaps can be identified.

**Why this priority**: All 14 existing agent archetypes use LangChain, CrewAI, or MCP. Bedrock and AgentCore have dedicated adapters but no test coverage, meaning framework-specific tool call formats or response parsing issues could go undetected.

**Independent Test**: Can be tested by verifying that new agent YAML files load correctly and are referenced by at least one ground truth scenario each.

**Acceptance Scenarios**:

1. **Given** a Bedrock agent archetype definition, **When** it is loaded by the ground truth schema, **Then** it validates successfully with the correct framework field and tool definitions.
2. **Given** an AgentCore agent archetype definition, **When** it is loaded by the ground truth schema, **Then** it validates successfully with the correct framework field and tool definitions.
3. **Given** at least one ground truth scenario referencing each new archetype, **When** the accuracy benchmark runs, **Then** results include findings attributed to the Bedrock and AgentCore frameworks.

---

### User Story 4 - Business Impact in Reports (Priority: P2)

As a security engineer or executive reviewing scan results, I want findings categorized by business impact (financial loss, reputation damage, privacy violation, etc.) so that I can prioritize remediation by organizational risk rather than technical attack type.

**Why this priority**: The business impact model already exists in the codebase but is not consistently surfaced. Making it a first-class citizen in reports enables non-technical stakeholders to understand scan results and prioritize remediation.

**Independent Test**: Can be tested by running a scan and verifying that Markdown, HTML, and JSON reports include business impact categorization per finding and an aggregate impact summary.

**Acceptance Scenarios**:

1. **Given** a completed scan with findings across multiple attack categories, **When** a Markdown report is generated, **Then** it includes a business impact summary table showing finding counts per impact category.
2. **Given** a finding for a data exfiltration attack with critical severity, **When** the report displays it, **Then** the business impact field shows "Privacy Violation" and "Financial Loss" (as derived from the existing mapping logic).
3. **Given** a completed scan, **When** a JSON report is generated, **Then** each finding includes a `business_impact` array with the mapped impact categories.
4. **Given** ground truth scenarios with known attack categories and severities, **When** the accuracy benchmark runs, **Then** each scenario's expected business impact is validated against the mapping function.

---

### Edge Cases

- What happens when an attack category has no business impact mapping? The system should fall back to an empty list and log a warning rather than failing.
- What happens when a ground truth scenario references a non-existent agent archetype? The schema validation should reject it with a clear error message.
- What happens when the LLM judge detector is disabled (no LLM provider configured)? Scenarios expecting the LLM judge should be skipped gracefully in the accuracy benchmark.
- What happens when a single finding maps to multiple business impact categories? All applicable categories should be listed (the existing mapping already supports this).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Ground truth dataset MUST include at least 4 true-positive and 2 true-negative scenarios for the authorization detector covering BOLA and BFLA patterns.
- **FR-002**: Ground truth dataset MUST include at least 3 true-positive and 2 true-negative scenarios for the LLM judge detector covering subtle/ambiguous attacks.
- **FR-003**: Ground truth dataset MUST include a multi-tenant SaaS agent archetype with tools that expose authorization boundaries (account-scoped data access, role-scoped operations).
- **FR-004**: Ground truth dataset MUST include at least one Bedrock agent archetype and one AgentCore agent archetype with framework-appropriate tool definitions.
- **FR-005**: Each new ground truth scenario MUST follow the existing schema (scenario_id, agent_ref, source, attack, ground_truth with expected_detectors).
- **FR-006**: Each new ground truth scenario MUST include an `expected_business_impact` field listing the business impact categories expected for that scenario.
- **FR-007**: Markdown reports MUST include a business impact summary table aggregating findings by impact category.
- **FR-008**: JSON reports MUST include `business_impact` on each finding.
- **FR-009**: The accuracy benchmark MUST compute precision and recall for the authorization detector and LLM judge detector using the new scenarios.
- **FR-010**: All new scenarios MUST have valid `owasp_mapping` entries consistent with their attack category.

### Key Entities

- **GroundTruthScenario**: Test case with agent reference, attack configuration, and expected detection outcomes. Extended with `expected_business_impact`.
- **AgentArchetype**: YAML definition of a test agent with framework, tools, system prompt, guardrails, and known vulnerabilities.
- **BusinessImpact**: Enumeration of organizational risk categories (financial loss, reputation damage, privacy violation, unauthorized actions, system compromise, misinformation, property loss).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Ground truth dataset grows from 54 to at least 65 scenarios (11+ new scenarios across authorization, LLM judge, and framework categories).
- **SC-002**: Authorization detector has measurable precision and recall in the accuracy benchmark (currently unmeasurable due to zero scenarios).
- **SC-003**: LLM judge detector has measurable precision and recall in the accuracy benchmark (currently unmeasurable due to zero scenarios).
- **SC-004**: All 5 built-in detectors (Refusal, Indicator, SideEffect, Authorization, LLMJudge) have at least 2 ground truth scenarios each.
- **SC-005**: Bedrock and AgentCore frameworks each have at least 1 agent archetype and 1 ground truth scenario.
- **SC-006**: 100% of scan findings in reports include business impact categorization.
- **SC-007**: All existing tests continue to pass (no regressions).
