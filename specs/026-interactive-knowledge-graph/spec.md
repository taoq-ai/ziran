# Feature Specification: Interactive Knowledge Graph Visualization

**Feature Branch**: `026-interactive-knowledge-graph`
**Created**: 2026-06-22
**Status**: Draft
**Input**: User description: "Interactive knowledge graph: richer, less-flat visualization in UI + report (GitHub issue #331). Full feature P1–P4, both surfaces (web UI + embedded HTML report) sharing one styling/mapping source of truth, including temporal phase scrubbing."

## Overview

The knowledge graph captured during a security campaign is structurally rich — it distinguishes 7 node kinds (agent, agent state, capability, tool, data source, vulnerability, phase) and 11 relationship kinds (tool use, data access, trust, enablement, chaining, discovery, exploitation, escalation, delegation, context sharing, trust boundary), and the system already computes betweenness centrality (chokepoints), dangerous capabilities, and attack paths. Today both viewing surfaces — the interactive web page and the self-contained HTML report — collapse all of that into a single uniform force-directed cloud where every node looks the same and no structure (phase progression, attack chains, criticality, multi-agent topology, growth over time) is legible at a glance.

This feature makes the graph **structured, weighted, interactive, temporal, and consistent across both surfaces**, so that a security analyst can read the shape of a campaign — which phase produced what, which nodes are pivotal, how an attack chains together, and how the picture grew turn by turn — without reading raw data.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Read campaign structure at a glance (Priority: P1)

A security analyst opens a completed run and wants to immediately understand the shape of what happened: which findings belong to which campaign phase, which nodes are pivotal to the attack surface, and how severe each discovery is — without manually untangling a uniform blob.

**Why this priority**: This is the core "it's too flat" complaint. Layout structure, importance encoding, and filtering deliver the largest perceived improvement and stand on their own as a shippable MVP.

**Independent Test**: Load a run with a populated graph, switch to the hierarchical-by-phase layout, confirm nodes are banded by campaign phase in methodology order, confirm pivotal nodes render visibly larger and higher-severity nodes render with stronger color/border emphasis, and confirm toggling a node type or severity band in the legend hides/shows the corresponding nodes.

**Acceptance Scenarios**:

1. **Given** a run whose graph has nodes discovered across multiple phases, **When** the analyst selects the hierarchical layout, **Then** nodes are arranged in left-to-right bands ordered by campaign phase (reconnaissance → … → exfiltration), with each node placed under the phase it was discovered in.
2. **Given** the same graph, **When** the analyst switches back to the force-directed layout, **Then** the graph re-renders in the physics-based layout and the analyst can switch between layouts repeatedly without losing the current filter/selection state.
3. **Given** a graph where centrality has been computed, **When** the graph renders, **Then** node size is proportional to each node's betweenness centrality so chokepoint nodes are visibly larger.
4. **Given** nodes with differing severity/risk, **When** the graph renders, **Then** color intensity and/or border emphasis reflect severity, and nodes representing dangerous capabilities carry a distinct visual marker.
5. **Given** the legend with type/severity/edge toggles, **When** the analyst disables a node type, an edge type, or a severity band, **Then** matching elements are hidden and the rest of the graph remains readable; re-enabling restores them.

---

### User Story 2 - Drill into large graphs and walk attack chains (Priority: P2)

An analyst facing a large or dense graph wants to collapse detail into manageable groups, expand only the area of interest, step through a discovered attack path one node at a time, and jump from a graph node to the related finding or attack-log entry (and back).

**Why this priority**: Once structure is legible (P1), interactivity is what turns the graph from a picture into an investigation tool. It depends on P1's styling/layout foundation but delivers distinct value.

**Independent Test**: Load a large multi-agent run, collapse a phase (or type) cluster into a super-node and expand it again, select a discovered attack path and step forward/back through its nodes with the focused node emphasized and surrounding context dimmed, click a node and land on its linked finding/attack-log card, and from a finding row focus its corresponding graph node.

**Acceptance Scenarios**:

1. **Given** a graph with many nodes, **When** the analyst collapses a phase or type group, **Then** its members are replaced by a single super-node labeled with the group and its member count, and expanding it restores the members.
2. **Given** a graph exceeding the large-graph threshold, **When** it first renders, **Then** it auto-clusters into super-nodes by default so the analyst sees a navigable overview rather than a hairball, with a clear way to expand.
3. **Given** a run with at least one discovered attack path, **When** the analyst starts the attack-chain walker and advances step by step, **Then** the current step's node is focused and its immediate context shown while the rest is de-emphasized, with forward/back controls and a position indicator.
4. **Given** a node that maps to a finding, attack-log entry, or OWASP-ATLAS technique, **When** the analyst clicks the node, **Then** the linked detail is surfaced and navigable; **and** when the analyst activates a finding row elsewhere on the page, the corresponding node is focused in the graph.
5. **Given** a multi-agent run, **When** the graph renders, **Then** delegation, trust-boundary, and context-sharing relationships are visually distinct, and agents and their subordinate nodes are grouped so trust topology is readable.

---

### User Story 3 - Watch the campaign grow over time (Priority: P3)

An analyst wants to scrub through the campaign phase by phase and watch the graph grow — seeing what each phase added — rather than only seeing the final end-state.

**Why this priority**: Temporal replay is high-value for understanding attack progression but requires per-phase snapshots to be surfaced through the data layer, so it builds on P1/P2 and is a meaningful but separable increment.

**Independent Test**: Load a multi-phase run, move a phase scrubber from the first phase to the last, and confirm the graph shows only the nodes/edges that existed up to (and including) the selected phase, growing as the scrubber advances; confirm attack-relevant edges are visually emphasized; confirm an empty graph shows a helpful empty state.

**Acceptance Scenarios**:

1. **Given** a run with multiple phase snapshots, **When** the analyst moves the phase scrubber to an earlier phase, **Then** the graph displays the state as of that phase (only nodes/edges discovered up to that point).
2. **Given** the scrubber at the last phase, **When** viewed, **Then** the graph matches the final end-state shown today.
3. **Given** a graph containing exploitation/chaining edges, **When** rendered, **Then** those attack-relevant edges are visually weighted/emphasized with clear directionality.
4. **Given** a run with no graph data (or a graph filtered down to nothing), **When** the analyst views it, **Then** a clear, helpful empty state is shown instead of a blank canvas.

---

### User Story 4 - Consistent graph across web UI and report (Priority: P1, enabling refactor)

A maintainer needs the interactive web view and the self-contained HTML report to render the graph from a single shared definition of node/edge styling and data mapping, so the two surfaces stop drifting and new visualization features land once for both.

**Why this priority**: Styling and mapping are duplicated across the two surfaces today. Unifying them early means every P1–P3 improvement is implemented once and appears consistently in both places, rather than twice with drift. It is an enabling refactor that should land alongside P1.

**Independent Test**: Define a node/edge style or mapping rule once, regenerate the HTML report and reload the web UI, and confirm both render the change identically without separate edits to each surface.

**Acceptance Scenarios**:

1. **Given** the shared graph styling/mapping definition, **When** a node type's color/shape/size or an edge type's style is changed in one place, **Then** both the web UI and the embedded HTML report reflect the change without surface-specific duplication.
2. **Given** the HTML report's self-contained constraint, **When** the report is generated, **Then** it remains a standalone artifact (no live backend dependency) while still consuming the same styling/mapping specification as the web UI.
3. **Given** the shared definition, **When** the analyst applies a layout, importance encoding, filter, or other supported control in either surface, **Then** the behavior is consistent across both surfaces to the extent each surface supports interactivity.

---

### Edge Cases

- **Empty graph**: A run with no discovered nodes shows a helpful empty state on both surfaces, not a blank canvas or an error.
- **Very large graph**: Above a defined node threshold, the graph auto-clusters and/or disables expensive physics so the view stays responsive instead of freezing into a hairball.
- **Missing phase attribution**: Nodes that cannot be attributed to a phase (no discovery linkage) are still rendered — grouped into an "unassigned" band in hierarchical layout — and never dropped.
- **Missing analytics**: When centrality/severity/risk data is absent for some nodes, importance encoding falls back to a sensible default size/color rather than failing to render.
- **Single-phase or single-node run**: Layout, scrubber, and clustering degrade gracefully (e.g., scrubber with one stop, no clustering needed).
- **No attack paths**: The attack-chain walker is unavailable or clearly disabled when a run has no discovered paths.
- **Non-multi-agent run**: Multi-agent topology elements are simply absent (not broken) when a run involves a single agent.
- **Report without per-phase data**: If per-phase snapshots are unavailable for an older run, the temporal scrubber gracefully falls back to showing the final state only.
- **Filter to empty**: When the analyst's filter selection hides every node, a helpful "nothing matches" state is shown with an easy reset.

## Requirements *(mandatory)*

### Functional Requirements

#### Layout & structure (P1)

- **FR-001**: The graph MUST offer selectable layout modes including at minimum a force-directed layout and a hierarchical-by-phase layout that bands nodes left-to-right in campaign-methodology phase order.
- **FR-002**: In the hierarchical layout, the system MUST place each node under the phase in which it was discovered, ordering phases by the established campaign methodology sequence.
- **FR-003**: The system SHOULD offer an additional centrality/radial layout that arranges nodes by importance, where feasible without library changes.
- **FR-004**: Switching layouts MUST preserve the analyst's current filters and selection where applicable.

#### Importance encoding (P1)

- **FR-005**: Node size MUST be proportional to the node's betweenness centrality so pivotal/chokepoint nodes are visibly larger.
- **FR-006**: Node color intensity and/or border emphasis MUST reflect severity or risk level for nodes that carry such data.
- **FR-007**: Nodes representing dangerous capabilities MUST carry a distinct, recognizable visual marker.
- **FR-008**: When centrality, severity, or risk data is missing for a node, the system MUST apply a sensible default visual weight rather than failing to render.

#### Filtering (P1)

- **FR-009**: The legend MUST double as a filter control, allowing the analyst to toggle visibility of node types, edge types, and severity bands.
- **FR-010**: Filtering MUST hide/show matching elements while keeping the remaining graph readable, and MUST be fully reversible.
- **FR-011**: The system MUST retain the existing text-search and path-highlight capabilities alongside the new filters.

#### Clustering & drill-down (P2)

- **FR-012**: The analyst MUST be able to collapse a group of nodes (by phase or by type) into a single super-node and expand it again on demand.
- **FR-013**: A super-node MUST be labeled to indicate the group it represents and how many members it contains.
- **FR-014**: When a graph exceeds a defined large-graph node threshold, the system MUST auto-cluster by default on first render and provide a clear way to expand clusters.

#### Attack-chain walker (P2)

- **FR-015**: For a run with discovered attack paths, the analyst MUST be able to select a path and step through it node-by-node with forward/back controls and a position indicator.
- **FR-016**: During walking, the current node MUST be focused with its immediate context visible while unrelated nodes are de-emphasized.
- **FR-017**: When a run has no discovered attack paths, the walker MUST be clearly unavailable/disabled rather than broken.

#### Cross-linking (P2)

- **FR-018**: Clicking a graph node MUST surface and allow navigation to its linked detail where one exists — finding, attack-log entry, and/or OWASP-ATLAS technique mapping.
- **FR-019**: Activating a finding (or equivalent) elsewhere on the run page MUST focus the corresponding node in the graph.

#### Multi-agent topology (P2)

- **FR-020**: For multi-agent runs, delegation, trust-boundary, and context-sharing relationships MUST be rendered as visually distinct edges.
- **FR-021**: For multi-agent runs, agents and their associated nodes MUST be grouped so the trust topology between agents is readable.

#### Temporal scrubbing (P3)

- **FR-022**: The system MUST persist and expose per-phase graph snapshots for a run (not only the final end-state) so the graph can be shown as of any completed phase.
- **FR-023**: The analyst MUST be able to move a phase scrubber to view the graph state as of a selected phase, with the graph growing as the scrubber advances toward the final phase.
- **FR-024**: At the final scrubber position, the displayed graph MUST equal the run's final end-state.
- **FR-025**: For runs lacking per-phase snapshots (e.g., older runs), the scrubber MUST gracefully fall back to showing the final state only.

#### Edge semantics & large/empty UX (P3)

- **FR-026**: Attack-relevant edges (exploitation and chaining relationships) MUST be visually weighted/emphasized with clear directionality.
- **FR-027**: An empty graph — whether genuinely empty or filtered to nothing — MUST show a helpful empty/"nothing matches" state with an easy reset, on both surfaces.

#### Shared source of truth (P4)

- **FR-028**: The node/edge styling and the data-to-visual mapping MUST be defined in a single shared specification consumed by both the web UI and the embedded HTML report.
- **FR-029**: A change to the shared styling/mapping MUST take effect in both surfaces without surface-specific duplication.
- **FR-030**: The HTML report MUST remain a self-contained, standalone artifact (no live backend dependency) while consuming the shared styling/mapping specification.
- **FR-031**: Both surfaces MUST present consistent layout, encoding, and filter behavior to the extent each surface supports interactivity (the report may offer a reduced-interactivity subset, but its visual language and mapping MUST match the web UI).

### Key Entities *(include if feature involves data)*

- **Graph node**: A discovered element of the campaign. Carries a type (agent, agent state, capability, tool, data source, vulnerability, phase), a discovering phase, and optional analytics attributes (centrality, severity/risk, dangerous flag) used for importance encoding and filtering.
- **Graph edge**: A directed relationship between two nodes, carrying a relationship type (tool use, data access, trust, enablement, chaining, discovery, exploitation, escalation, delegation, context sharing, trust boundary) and optional attributes (e.g., risk, chain position) used for semantic emphasis.
- **Phase snapshot**: The state of the graph as captured at the end of a campaign phase, used to drive the temporal scrubber. Ordered by campaign methodology.
- **Attack path**: An ordered sequence of nodes representing a discovered chain from a capability/tool toward a vulnerability or sensitive data source, used by the attack-chain walker.
- **Critical node**: A node identified as a chokepoint by centrality analysis, used to drive importance encoding.
- **Cross-link target**: A finding, attack-log entry, or OWASP-ATLAS technique associated with a node, used for node↔detail navigation.
- **Shared graph style/mapping spec**: The single canonical definition of how node/edge data maps to visual properties (color, shape, size, emphasis) and control behavior, consumed by both rendering surfaces.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Given a multi-phase run, an analyst can identify which phase produced a given node within 10 seconds using the hierarchical layout, without inspecting raw data.
- **SC-002**: The most central (chokepoint) nodes are visually distinguishable by size from peripheral nodes in 100% of runs that have computed centrality.
- **SC-003**: An analyst can isolate a single node type or severity band (hiding all others) in 3 or fewer interactions.
- **SC-004**: A graph above the large-graph threshold renders an initial navigable view (auto-clustered) without the interface becoming unresponsive.
- **SC-005**: For any run with at least one discovered attack path, an analyst can step through the full path end-to-end using only the walker controls.
- **SC-006**: From a graph node with a linked finding, an analyst reaches that finding's detail (and back to the node) without leaving the run view.
- **SC-007**: Moving the phase scrubber across all phases shows a strictly non-decreasing graph (nodes only appear, never disappear, as the scrubber advances), ending at the final end-state.
- **SC-008**: A single change to the shared styling/mapping definition is reflected identically in both the web UI and a freshly generated HTML report, verified with zero surface-specific edits.
- **SC-009**: The HTML report continues to open and render fully as a standalone file with no backend access; the only permitted network dependency is the vis-network graph library loaded from a CDN (no API or database connectivity required).
- **SC-010**: Empty and filtered-to-empty graphs always present a helpful state (never a blank canvas or error) on both surfaces.

## Assumptions

- The visualization continues to use the existing graph-rendering library family on both surfaces; no library replacement is required because the needed capabilities (hierarchical layout, clustering) are already available.
- Campaign phases follow the existing fixed methodology ordering (reconnaissance → trust building → capability mapping → vulnerability discovery → exploitation setup → execution → persistence → exfiltration).
- Per-phase graph snapshots are computed in memory during a run today; making temporal scrubbing work requires persisting and exposing them through the data layer, and older runs without stored snapshots fall back to final-state-only.
- Phase attribution for a node is derived from its discovery linkage to a phase; nodes without such linkage are grouped as "unassigned" rather than dropped.
- The HTML report targets full visual + interaction parity with the web UI (layout modes, encoding, filters, clustering, attack-chain walker, and phase scrubber via per-phase snapshots embedded inline so they work offline). Live, backend-resolved cross-linking is the one exception — the report uses intra-document anchors instead. To keep the standalone file manageable, embedded per-phase snapshots reuse the shared mapping and avoid duplicating large payloads beyond what each phase adds; if a report exceeds a practical size, snapshot embedding may be capped (and the cap surfaced in the report).
- "Severity/risk" and "dangerous capability" signals are already present on the relevant nodes where applicable; encoding uses whatever signal exists and degrades gracefully when absent.

## Dependencies

- Existing knowledge-graph analytics (centrality/critical nodes, attack-path discovery, dangerous-capability detection) remain the source of importance and chaining data.
- The run data layer must be extended to persist and serve per-phase graph snapshots for temporal scrubbing.
- Findings, attack-log, and OWASP-ATLAS associations must be resolvable from a node for cross-linking.
