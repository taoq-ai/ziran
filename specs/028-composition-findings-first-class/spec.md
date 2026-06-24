# Feature Specification: Tool-composition chains as first-class findings

**Feature Branch**: `feat/028-composition-findings-first-class`
**Created**: 2026-06-24
**Status**: Active
**Input**: Composition analysis is Ziran's differentiator, but a `DangerousChain` from
`ToolChainAnalyzer` is not surfaced as a finding: it does not affect `CampaignResult.success`,
is never added to the knowledge graph (so the interactive report shows no red node for it), and
is ignored by the CI quality gate. A scan whose only finding is a **critical** tool-composition
exfiltration chain therefore reports "0 vulnerabilities / passed" with a clean graph. (Surfaced
while preparing the "When Your Agent Tools Combine Against You" talk on ziran v0.36.0; the prior
red node had been a detector false positive that spec-027 correctly removed.)

## User Scenarios & Testing *(mandatory)*

### User Story 1 — A critical composition is a finding (Priority: P1)
A security analyst scans an agent that has no *confirmed* exploit but whose tools compose into a
critical `data_exfiltration` chain (e.g. `search_database → send_email_report`). The scan result
must register this as a finding: `success = true`, the chain visible in the report **graph as a
red node**, and the CLI summary stating a critical composition was found — not "passed".

**Independent Test**: Build a graph with the two tools + a `can_chain_to` edge, run the campaign
result builder, assert `success is True`, that `export_state()` contains a `vulnerability` node
for the composition, and that the scan summary surfaces it.

**Acceptance Scenarios**:
1. **Given** a graph whose `ToolChainAnalyzer` yields one critical chain, **When** the
   `CampaignResult` is built, **Then** `success` is `True` and a `NodeType.VULNERABILITY` node
   (category `tool_composition`, severity `critical`) exists in the graph linked by `EXPLOITS`
   edges to the chain's tools.
2. **Given** that result, **When** `ziran ci` evaluates it against the default gate
   (`max_critical_findings: 0`), **Then** the gate **fails** with a critical composition finding.

### User Story 2 — Detector precision is preserved (Priority: P1)
The spec-027 fix must not regress: an agent that merely *describes* its tools is still **not** a
finding. Composition findings come from the tool graph, never from topical words in a response.

**Independent Test**: The spec-027 detection-accuracy benchmark and
`det_borderline_capability_data_analyst_001` stay green; a new borderline case asserts the
*composition* IS a finding while the *self-description* is NOT.

### User Story 3 — Latent vs confirmed stays distinguishable (Priority: P2)
A composition is a *latent* finding (a path that exists) vs a detector-*confirmed* exploit. The
result must keep them distinguishable (e.g. `finding_source: "composition"` on the node and a
`composition_finding_count` / breakdown in metadata), so reports can label them.

## Requirements *(mandatory)*
- **FR-001**: `AttackKnowledgeGraph` MUST expose a method to register a `DangerousChain` as a
  `VULNERABILITY` node (severity = chain risk level, category `tool_composition`) linked to the
  chain's tools via `EXPLOITS` edges.
- **FR-002**: `ResultBuilder.build()` MUST register every dangerous chain on the graph before
  exporting state, and MUST set `success = True` when a critical (or high, configurable)
  composition chain is present.
- **FR-003**: The CI quality gate MUST count dangerous chains by severity alongside detector
  findings, so a critical composition fails the default gate.
- **FR-004**: The `scan` CLI summary MUST present composition findings in the headline verdict,
  not only as a side count.
- **FR-005**: Composition findings MUST remain distinguishable from detector-confirmed findings
  (source label + metadata breakdown).
- **FR-006**: Markdown/JSON reports MUST continue to render the dangerous-chains section.
- **FR-007**: Regression tests MUST prove FR-001..004 and that spec-027 precision is preserved.

## Success Criteria *(mandatory)*
- **SC-001**: A scan whose only finding is a critical composition reports `success = true`, a red
  composition node in the graph, and a failing `ziran ci` gate.
- **SC-002**: spec-027 benchmarks unchanged (no false-positive regression); precision/recall hold.
- **SC-003**: All gates pass — lint, format, mypy (strict), pytest coverage ≥ 85%.
