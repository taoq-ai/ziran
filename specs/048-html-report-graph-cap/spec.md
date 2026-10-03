# Feature Specification: cap the HTML report knowledge-graph payload and escape its inlined JSON

**Feature Branch**: `048-html-report-graph-cap`
**Created**: 2026-10-03
**Status**: Active
**Issue**: #217 ("perf: HTML report embeds entire graph as JSON without pagination"), release 0.41.0
batch "gates you can leave on".
**Siblings (parallel, no shared file)**: #447 / spec 045 (`mcp_metadata_analyzer.py`), #395 / spec
046 (`ziran ci`, `ziran/application/cicd/*`), #399 / spec 047 (`ziran scan`, LLM usage). This spec
touches only `ziran/interfaces/cli/html_report.py`, `tests/unit/test_html_report.py` and two docs
pages; it does not touch `ziran/interfaces/cli/main.py`.
**Input**: `build_html_report` (`ziran/interfaces/cli/html_report.py`) inlines four JSON blobs into
one `<script>`: the final graph's vis nodes and edges, every critical path, and a full vis copy of
the graph for **every** phase snapshot (`_build_phase_states`, spec 026 US3). Nothing is capped.

**Measured today** (`develop` @ 7d4132e, scratch script calling `build_html_report` on a synthetic
8-phase campaign whose phase `k` snapshot holds `k/8` of the vulnerabilities):

| Final graph | HTML bytes | Build time |
|---|---|---|
| 108 nodes / 599 edges | 1,473,591 | 0.02-0.03 s |
| 708 nodes / 5,699 edges | 12,438,481 | 0.09-0.15 s |

One vis node serializes to ~445 bytes and one vis edge to ~324 bytes. The empty report is 27,789
bytes. The per-phase snapshots, not the final graph, multiply the size (9 graph copies in the
example above).

**Security defect (found while reading the code)**: the four blobs are produced by plain
`json.dumps` and placed raw between `<script>` and `</script>` (template line ~1289). `json.dumps`
does not escape `<`, `/` or `>`, so a node `name` (used verbatim as the vis `label`), a node id, a
tool name or a vector name containing `</script>` ends the script element early and the rest of the
string is parsed as HTML. A tool name is attacker-controlled (it comes from the scanned agent or MCP
server), so this is a stored-XSS vector in a report users open locally.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — A large campaign produces a report that opens quickly (Priority: P1)
An operator runs a campaign with hundreds of vulnerabilities and thousands of graph edges. The HTML
report embeds a bounded, risk-ranked subset of the graph instead of all of it.

**Why this priority**: The issue's problem statement; a 12 MB report with 9 copies of the graph is
slow to write and slow to render in vis-network.

**Independent Test**: a synthetic `graph_state` with 700+ nodes and 5,000+ edges passed to
`build_html_report`; parse the inlined `rawNodes` / `rawEdges` / `phaseStates` back out of the HTML.

**Acceptance Scenarios**:
1. **Given** a graph state with more than `_MAX_VIS_NODES` nodes and more than `_MAX_VIS_EDGES`
   edges, **When** `build_html_report` runs, **Then** `rawNodes` has at most `_MAX_VIS_NODES` entries
   and `rawEdges` at most `_MAX_VIS_EDGES`, and every edge's `from` and `to` is the id of a node in
   `rawNodes`.
2. **Given** the reference synthetic campaign (plan §Reference fixture: 708 nodes / 5,699 edges, 8
   phase snapshots), **When** the report is built, **Then** the HTML is at most 2,000,000 bytes
   (today 12,438,481).
3. **Given** a graph at or under both caps, **When** the report is built, **Then** the node and edge
   lists are exactly today's (same ids, same order, same vis properties) and no truncation notice is
   rendered.

### User Story 2 — The highest-risk part of the graph is what survives (Priority: P1)
**Why this priority**: A capped graph that drops the findings is worse than a slow one.

**Independent Test**: synthetic graph whose nodes differ only in severity, `dangerous`, centrality
and type; call `_cap_graph_state` directly.

**Acceptance Scenarios**:
1. **Given** critical paths in `result_data["critical_paths"]`, **When** the graph is capped,
   **Then** every node of the first `_MAX_RENDERED_PATHS` (20) paths that exists in the graph is
   kept, and so is every edge joining two consecutive nodes of one of those paths, even when those
   nodes have no severity, are not dangerous and have centrality `0.0`.
2. **Given** phase nodes (`node_type == "phase"`), **Then** all of them are kept.
3. **Given** more vulnerability nodes than free slots, **Then** vulnerability nodes fill the free
   slots before any other node type, highest severity first (`critical > high > medium > low >`
   anything else).
4. **Given** non-vulnerability nodes competing for the remaining slots, **Then** they are ranked by
   severity, then `dangerous` (true first), then centrality (higher first), then node type (plan
   §2 order), then original position; centrality `0.0` everywhere (graphs above
   `_MAX_CENTRALITY_NODES = 800` nodes in `graph.py`) still yields a deterministic ranking.
5. **Given** more surviving edges than `_MAX_VIS_EDGES`, **Then** critical-path edges are kept first,
   attack edges (`GraphStyleSpec.is_attack_edge`: `exploits`, `can_chain_to`, `leads_to`) next,
   then the rest, each group in original order.

### User Story 3 — The phase timeline scrubber is bounded too (Priority: P1)
**Why this priority**: The per-phase snapshots are the size multiplier (spec 026).

**Independent Test**: `result_data["phases_executed"]` with 8 phases, each snapshot above the caps;
call `_build_phase_states`.

**Acceptance Scenarios**:
1. **Given** phase snapshots above the caps, **When** `_build_phase_states` runs, **Then** each
   returned stop has at most `_MAX_VIS_NODES` nodes and `_MAX_VIS_EDGES` edges, keeps the
   `{"label", "nodes", "edges"}` shape, and keeps the critical-path nodes present in that snapshot.
2. **Given** legacy runs with no snapshots, **Then** `_build_phase_states` still returns `[]` and the
   scrubber stays hidden (existing tests unchanged).

### User Story 4 — The report says when it is showing a subset (Priority: P1)
**Acceptance Scenarios**:
1. **Given** the final graph was truncated (fewer nodes or fewer edges embedded than the graph
   state holds), **When** the report renders, **Then** the "Knowledge Graph" sidebar section shows
   `Showing N of M nodes and K of L edges (highest-risk first).` where `M` / `L` are the lengths of
   `graph_state["nodes"]` / `graph_state["edges"]` and `N` / `K` the embedded counts.
2. **Given** no truncation, **Then** no notice element is rendered.
3. The sidebar "Nodes" / "Edges" metrics keep showing the full `stats` totals.

### User Story 5 — Inlined JSON cannot break out of the script element (Priority: P1, security)
**Acceptance Scenarios**:
1. **Given** a node whose `name` and `id` are `</script><b>x`, a critical path containing that id,
   and a phase snapshot containing that node, **When** the report is built, **Then** the HTML
   contains exactly two `</script>` occurrences (the vis-network CDN tag's and the data script's
   own), the substring `</script><b>x` never appears, and the text of the `const rawNodes = ...;`
   line parses with `json.loads` back to a node whose `label` and `id` are `</script><b>x`.
2. **Given** a node name containing `<!--<script>`, **Then** the substring `<!--` does not appear
   inside the data script.
3. All four blobs (`rawNodes`, `rawEdges`, `criticalPaths`, `phaseStates`) go through the same
   escaping helper.

### Edge Cases
- A node with no `severity`, `dangerous`, `centrality` or `node_type` ranks last within its tier
  (severity -1, not dangerous, centrality 0.0, unknown type after all known ones).
- Severity is matched case-insensitively (`"HIGH"` ranks as `high`); a non-string severity is
  treated as unknown.
- Edges whose endpoint is not in the input node list (dangling) are passed through unchanged when
  the graph is under both caps (today's behaviour); above a cap they are dropped with every other
  edge whose endpoints are not both kept.
- If the always-kept set (critical-path nodes of the first 20 paths plus phase nodes) is larger
  than `_MAX_VIS_NODES`, all of it is kept and nothing else is: the node count is
  `max(_MAX_VIS_NODES, len(always_kept))`. In practice paths have at most 6 nodes
  (`find_all_attack_paths(max_path_length=5)`), so the always-kept set is at most
  `20 * 6 + phases`, below the cap.
- `criticalPaths` in the page is truncated to the first `_MAX_RENDERED_PATHS` paths: they are the
  only ones `highlightPath(i)` can be called with (the sidebar renders 20 path items and an
  "...and N more paths" line, unchanged). `result_data["critical_paths"]` may hold up to 10,000
  paths. The "Attack Paths" metric keeps the full count.
- The truncation notice describes the final graph only; phase stops are capped silently with the
  same rule (each is a view of the same campaign).
- Highlighting a path whose edges are not consecutive in the graph (none exist between two path
  nodes) behaves as today.

## Requirements *(mandatory)*

### Functional Requirements
- **FR-001 (caps)**: Module constants in `html_report.py`: `_MAX_VIS_NODES = 150`,
  `_MAX_VIS_EDGES = 300`, `_MAX_RENDERED_PATHS = 20` (the literal `20` in `_build_paths_html`
  becomes this constant; its output is unchanged).
- **FR-002 (cap function)**: `_cap_graph_state(graph_state, paths)` returns the input object
  unchanged when it has at most `_MAX_VIS_NODES` nodes and at most `_MAX_VIS_EDGES` edges;
  otherwise a shallow copy with `nodes` / `edges` replaced by the capped lists, built by the ranking
  of US2 (plan §2). Pure, no I/O, does not mutate its input.
- **FR-003 (final graph)**: `build_html_report` caps `graph_state` with
  `paths[:_MAX_RENDERED_PATHS]` before `graph_state_to_vis`.
- **FR-004 (phase stops)**: `_build_phase_states` caps every snapshot with the same function and
  the same paths before `graph_state_to_vis`; stop shape unchanged.
- **FR-005 (paths blob)**: the page's `criticalPaths` is `paths[:_MAX_RENDERED_PATHS]`.
- **FR-006 (notice)**: a new template placeholder `{graph_notice_html}` inside the "Knowledge Graph"
  section, filled with `<p class="muted" id="graphCapNotice">Showing N of M nodes and K of L edges
  (highest-risk first).</p>` when truncated, `""` otherwise.
- **FR-007 (escaping)**: a helper `_script_json(value)` returns `json.dumps(value)` with every `<`
  replaced by `<`; all four blob placeholders use it. This is a strict superset of escaping
  `</` as `<\/` (the planner's minimum): it also neutralizes `<!--`, which can otherwise put the
  HTML parser into the script "double-escaped" state and swallow the closing tag. `<` is a
  valid JSON and JS string escape, so the page reads identical values.
- **FR-008 (unchanged surface)**: `graph_state_to_vis`, `build_html_report` signatures, the template
  JS (`highlightPath`, `showPhase`, filters, clustering) and `ReportGenerator.save_html` are
  unchanged. No new dependency, no new CLI flag, no config key.
- **FR-009 (docs)**: one sentence in `docs/concepts/knowledge-graph.md` §Visualization stating that
  the HTML report embeds at most 150 nodes and 300 edges per view (critical paths, phases and
  findings first) and says so when it truncates; the web UI is unaffected. `docs/community/
  roadmap.md` #217 line ticked.

### Assumptions (recorded, most conservative reading)
- The issue's fix 1 ("limit to top N by centrality/risk, e.g. 100") is implemented; fixes 2
  (streaming JSON), 3 (separate JSON file: breaks the self-contained report and `file://` fetch) and
  4 (attack-log pagination) are out of scope per the release planner.
- Caps 150 / 300 instead of the issue's example 100: the always-kept set alone can reach
  `20 * 6 + 8 = 128` nodes. 150 nodes is under the web UI's own auto-cluster threshold
  (`large_graph_node_threshold = 200`). Not configurable (YAGNI); change the constants if needed.
- Phase stops are capped (planner option 1) rather than turned into id references (option 2): it
  keeps the stop shape and `showPhase` unchanged and keeps each phase's own node styling. The
  scratch projection with 150 / 300 caps on the reference fixture gave 1,059,721 bytes (naive slice,
  not the ranking, no escaping). Upper bound with FR-007 escaping (`<` -> 6 bytes in tooltips): the
  largest escaped vis node in the fixture is 600 bytes and the largest edge 356 (scratch measure),
  so 9 views give at most `9 * (150 * 600 + 300 * 356) + 27,789 = 1,798,989` bytes; the US1.2 budget
  of 2,000,000 holds by construction for that fixture.
- "Always keep vulnerability nodes" is read as "vulnerability nodes outrank every non-pinned node";
  a hard guarantee for all of them would make the cap unbounded (one node per finding).
- The notice is static text; no "show all" toggle (the full graph is not in the page).

### Out of scope (follow-ups)
- The `capabilities x vulnerabilities` `ENABLES` fan-out in `AgentScanner._update_graph_from_phase`
  (`ziran/application/agent_scanner/scanner.py` ~line 667) is the root of most edges in real
  graphs. Reducing it is a separate change: `find_all_attack_paths` depends on those edges, and
  `scanner.py` is at its 750-line cap.
- Streaming JSON, a separate data file, attack-log pagination, a configurable cap.

### Key Entities
- No new Pydantic model: the inputs are the existing `export_state()` dicts and the outputs the
  existing vis dicts (the module is typed `dict[str, Any]` today; FR-008).

## Success Criteria *(mandatory)*

### Measurable Outcomes
- **SC-001**: US1-US5 pass as unit tests in `tests/unit/test_html_report.py` on synthetic graphs (no
  network, no LLM, no browser).
- **SC-002**: The reference fixture's report is at most 2,000,000 bytes and each of its `rawNodes`,
  `rawEdges` and every phase stop is within the caps; the PR reports the measured byte count from
  the test or a command actually run.
- **SC-003**: Every pre-existing test in `tests/unit/test_html_report.py` and
  `tests/unit/test_reports.py` passes unmodified (including the phase-scrubber and
  `highlightPath`/path-item tests).
- **SC-004**: All gates pass: ruff, ruff format, mypy strict, pytest coverage >= 85%; no new
  dependency; `uv.lock` unchanged.
- **SC-005 (unverified offline)**: browser render time of a capped report is not measured (no
  headless browser in the test suite); the byte budget is the offline proxy.
