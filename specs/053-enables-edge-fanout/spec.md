# Feature Specification: reduce the capabilities x vulnerabilities ENABLES edge fan-out

**Feature Branch**: `053-enables-edge-fanout`
**Created**: 2026-10-04
**Status**: Active
**Issue**: #451 (release 0.42.0, "faster scans, truer graphs" batch, pass 2). Follow-up from #217 /
PR #449 (spec 048, out of scope there).
**Base**: `develop` @ 7e1ef38 (pass 1 merged: spec 049 scan cache, spec 050 LangGraph-native
scanning, spec 051 probe delay, spec 052 web route tests).
**Siblings (parallel, separate worktrees)**: #327 / spec 054 (benchmark PR delta), #264 / spec 055
(ATLAS coverage docs). No shared file: this feature touches
`ziran/application/agent_scanner/scanner.py` (`_update_graph_from_phase` only), one new
`agent_scanner` sub-module, one comment in `ziran/application/knowledge_graph/graph.py`, one row in
`docs/concepts/knowledge-graph.md` and one new test file.
**Input**: `AgentScanner._update_graph_from_phase` adds an `ENABLES` edge from **every** capability
node to **every** vulnerability found in the phase. The capabilities x vulnerabilities cross
product dominates real knowledge graphs, the web UI graph payload and `find_all_attack_paths`.
PR #449 only capped what the HTML report embeds. `find_all_attack_paths` depends on these edges,
so the reduction must keep the attack paths it finds today or justify each loss.

## Current behaviour (read on `develop` @ 7e1ef38)

- Capabilities are added by `AgentScanner._discover_and_map_capabilities` (one `CAPABILITY` node
  per `AgentCapability`, id = `cap.id`, attributes `data=cap.model_dump()`, `dangerous`). A
  dangerous capability also gets `cap -> sensitive_data` (`ACCESSES_DATA`). Since spec 050,
  `import_adapter_structure` may add `AGENT` nodes (`agent -> cap` `USES_TOOL`) and `AGENT_STATE`
  nodes (`writer cap -> state:<channel> -> reader cap` `ACCESSES_DATA`).
- `PhaseExecutor.execute` adds a `VULNERABILITY` node per successful vector and records
  `result.artifacts[vector_id]["evidence"] = AttackResult.evidence`. Both success paths
  (`AttackExecutor.execute` single-turn and `TacticExecutor` multi-turn) put
  `"tool_calls": response.tool_calls` and
  `"side_effects": get_side_effect_summary(response.tool_calls)` in that evidence;
  `side_effects["tools_invoked"]` is the list of tool names of the calls (the `tool` / `name` /
  `function.name` conventions, `SideEffectDetector._extract_tool_name`). Adapters that implement
  `observe_tool_call` fold the observed calls into `response.tool_calls` (e.g. `MockAgentAdapter`,
  LangChain), so they reach the same field. Cache hits (spec 049) replay the stored evidence.
- `_update_graph_from_phase` then adds `vuln -> phase_<name>` (`DISCOVERED_IN`) and, for every
  `CAPABILITY` node, `cap -> vuln` (`ENABLES`, `{"phase": ...}`). Only `CAPABILITY` nodes are
  linked; `TOOL`, `AGENT` and `AGENT_STATE` nodes are not.
- `ResultBuilder.build` runs `ToolChainAnalyzer` (composition findings: `tool -> composition vuln`
  `EXPLOITS`) and then `critical_paths = graph.find_all_attack_paths()`: every simple path of at
  most 5 hops from a `CAPABILITY`/`TOOL` node to a `VULNERABILITY`/`DATA_SOURCE` node.
- Vulnerability nodes have only outgoing `DISCOVERED_IN` edges to phase nodes (not path targets,
  no outgoing edges), so an `ENABLES` edge can only ever be the **last hop** of an attack path.
  Every path that uses an `ENABLES` edge is either `[cap, vuln]` or
  `[..., cap, vuln]` through state/agent structure (e.g. `[capA, state:x, capB, vuln]`).

Measured on `develop` @ 7e1ef38 (offline, `MockAgentAdapter(vulnerable=True)` with six
capabilities, three dangerous, phases `reconnaissance` + `vulnerability_discovery`, default
`AttackLibrary`; scratch script, not committed): 6 vulnerabilities, edges
`{"enables": 36, "accesses_data": 3, "discovered_in": 6}`, `len(critical_paths) == 39`
(36 `[cap, vuln]` + 3 `[cap, sensitive_data]`), and every vulnerability's evidence had
`tools_invoked == ["shell_execute"]`. 30 of the 36 `ENABLES` edges link a capability the
successful attack never invoked.

## User Scenarios & Testing *(mandatory)*

Shared fixtures (all offline, no adapter I/O beyond `MockAgentAdapter`):
- **Legacy linker**: a test-local copy of today's loop (`for cap in CAPABILITY nodes:
  add_edge(cap, vuln, ENABLES, {"phase": ...})`) - the "before" reference captured from the
  current code.
- **Representative graph**: capabilities `tool_read_inbox` (benign), `tool_send_email` (benign),
  `tool_shell_execute` (dangerous), `tool_get_weather` (benign), `tool_calculator` (benign),
  `tool_read_file` (dangerous); `sensitive_data` links for the dangerous ones (as discovery adds
  them); a spec-050 topology imported with `import_structure` (one agent using the inbox and email
  tools, state channel `messages` written by `tool_read_inbox` and read by `tool_send_email`);
  vulnerabilities whose evidence names invoked tools (`vuln_exfil` -> `send_email`, `vuln_rce` ->
  `shell_execute`), one with no tool calls (`vuln_pi`), one naming a tool that is not a capability
  (`vuln_ghost` -> `delete_everything`).

### User Story 1 - A vulnerability is linked only to the capabilities implicated in it (Priority: P1)

An operator scanning a tool-using agent sees each finding connected to the tools the successful
attack actually used, not to every tool the agent has.

**Why this priority**: the issue's whole ask; removes the cross product.

**Independent Test**: build a graph with capability nodes, call the selection function / the
scanner's `_update_graph_from_phase` with a `PhaseResult` carrying evidence, inspect the
`ENABLES` edges.

**Acceptance Scenarios**:
1. **Given** a vulnerability whose evidence has `side_effects.tools_invoked == ["send_email"]`,
   **When** the phase is recorded, **Then** the only `ENABLES` edge into it starts at the
   capability whose node id **or** `data["name"]` equals `"send_email"` (`tool_send_email`).
2. **Given** `tools_invoked` naming two capabilities, **Then** exactly those two are linked.
3. **Given** `tools_invoked` empty, missing, malformed (not a dict / not a list) or naming only
   tools that are not capability nodes, **Then** the fallback applies (US2).
4. Non-`CAPABILITY` nodes (`TOOL`, `AGENT`, `AGENT_STATE`, data sources) are never linked, even
   when their id equals an invoked tool name (unchanged: today only capabilities are linked).
5. Edges keep today's shape: `edge_type="enables"`, attributes `{"phase": <phase value>}`.

### User Story 2 - Explicit fallback keeps every vulnerability reachable (Priority: P1)

When the evidence does not name any capability, the graph still connects the finding so attack-path
search does not lose it.

**Why this priority**: the issue's constraint (`find_all_attack_paths` depends on these edges).

**Acceptance Scenarios**:
1. **Given** no implicated capability and at least one dangerous capability, **Then** the
   vulnerability is linked from every dangerous capability and from nothing else.
2. **Given** no implicated capability and no dangerous capability, **Then** the vulnerability is
   linked from every capability (today's behaviour for that case; see "Kept edge class").
3. **Given** no capability nodes at all, **Then** no `ENABLES` edge is added (unchanged).
4. The returned order is graph node insertion order, so path output is deterministic.

### User Story 3 - Attack paths found today are kept or each loss is justified (Priority: P1)

**Why this priority**: issue constraint; consumers (CI gate, policy engine, reports, pentest tool)
read `critical_paths`.

**Acceptance Scenarios** (representative graph, legacy linker = "before", new rule = "after"):
1. **Given** the same graph built both ways, **Then** `after` is exactly `before` minus the paths
   whose last hop is a dropped `ENABLES` edge: every path whose final `(cap, vuln)` pair is in the
   expected kept-pair set (hard-coded in the test from the rule, not computed by the code under
   test), and every path that does not end in an `ENABLES` hop, is present in `after`; nothing in
   `after` is absent from `before`.
2. **Given** the same, **Then** the set of path endpoints is identical:
   `{p[-1] for p in before} == {p[-1] for p in after}` - no vulnerability or data source becomes
   unreachable.
3. **Then** the named critical paths are present in `after`:
   `[tool_read_inbox, "state:messages", tool_send_email, vuln_exfil]` (the spec-050 shared-state
   path), `[tool_send_email, vuln_exfil]`, `[tool_shell_execute, vuln_rce]`,
   `[tool_shell_execute, "sensitive_data"]`, and `vuln_pi` / `vuln_ghost` reached from both
   dangerous capabilities.
4. Paths through composition findings (`EXPLOITS`) and to `sensitive_data` (`ACCESSES_DATA`) are
   identical before and after (they do not use `ENABLES`).

### User Story 4 - The cross product is gone (Priority: P1)

**Acceptance Scenarios**:
1. **Given** 10 capabilities (2 dangerous) and 20 vulnerabilities, 15 of them with evidence
   naming one capability and 5 with no tool calls, **When** all are recorded, **Then** the graph
   has exactly `15 * 1 + 5 * 2 = 25` `ENABLES` edges (the legacy linker gives `10 * 20 = 200`),
   and `25 < (10 * 20) / 4`.
2. **Given** an end-to-end `AgentScanner.run_campaign` with `MockAgentAdapter(vulnerable=True)`
   (every successful attack invokes `shell_execute`) and the six capabilities of the measurement
   above, **Then** every `ENABLES` edge starts at `tool_shell_execute`, the `ENABLES` count equals
   the number of vulnerability nodes, every vulnerability is the last node of some
   `critical_paths` entry, and `len(critical_paths) == vulnerabilities + 3` (the three dangerous
   capabilities' `sensitive_data` paths). Today the same run gives `ENABLES == 6 * vulns`.

### Edge Cases
- **Kept edge class (tier 3, the concrete example)**: an agent whose capabilities are all benign
  (e.g. the `mock_adapter` fixture: one non-dangerous `tool_search`) and a prompt-injection finding
  with no tool calls. Today the only path to that finding is the cross-product edge
  `[tool_search, vuln]`; no implication rule (no invoked tool, no dangerous capability)
  reproduces it, so dropping it would remove the finding from `critical_paths`. The rule keeps
  that edge class: with no implicated and no dangerous capability, every capability is linked,
  exactly as today. The cross product therefore survives only for findings with no tool evidence
  on agents with no dangerous capability (proven by a dedicated test: `ENABLES == N * M` there).
- **Dropped paths (justified)**: `[benign_cap, vuln]` (and multi-hop paths ending in such an
  edge) when the successful attack invoked other tools, or invoked none and dangerous capabilities
  exist. Evidence: the attack's own tool calls (`side_effects.tools_invoked`) do not include that
  capability, and the vulnerability stays reachable through the implicated / dangerous ones
  (US3.2). These are the cross-product paths the issue targets.
- **Tool names that are not capabilities** (`vuln_ghost`): fall back to tier 2/3; no node is
  created for the unknown tool (no new nodes or edge types).
- **Same vulnerability recorded twice** (e.g. a resumed campaign re-running a phase): unchanged
  multigraph behaviour, one edge per call per linked capability, as today.
- **`max_paths` (10 000) cap**: `before` can be truncated on huge graphs; with fewer edges `after`
  may surface paths `before` cut off. Test graphs stay far below the cap.
- **ToolChainAnalyzer**: chain discovery is unaffected (vulnerabilities are sinks except for
  `DISCOVERED_IN` to sink phase nodes, so no tool-to-tool path ever ran through an `ENABLES`
  edge). The risk score's centrality bonus (`<= 0.15 * betweenness`) is computed on the whole
  graph and can shift for capabilities that have incoming edges (spec-050 agent/state structure);
  on flat graphs capability betweenness is 0 before and after. Accepted; existing chain-analyzer
  tests build no `ENABLES` edges and stay unchanged.
- **Downstream counts**: `len(critical_paths)` drops. `PolicyEngine` `max_critical_paths` rules
  may now pass where the inflated count failed (intended: the count no longer scales with the
  number of benign tools). The CI gate's pass/fail is unchanged (every vulnerability that ended a
  path is still counted as an unbacked phase vulnerability); only its "N unbacked critical
  path(s)" number shrinks. HTML report, web UI and pentest `query_graph` get fewer paths/edges;
  no code change there.

## Requirements *(mandatory)*

### Functional Requirements
- **FR-001 (selection rule)**: for each vulnerability in a phase, the `ENABLES` sources are
  chosen in this order, first non-empty tier wins:
  1. capability nodes whose node id or `data["name"]` equals a name in the vulnerability's
     `evidence["side_effects"]["tools_invoked"]`;
  2. else every capability node with `dangerous=True`;
  3. else every capability node (pre-053 behaviour).
- **FR-002 (placement)**: the rule lives in a new module
  `ziran/application/agent_scanner/enables_links.py` (< 400 lines), function
  `enabling_capabilities`; `scanner.py` calls it and its diff is net-zero or negative
  (it stays <= 750 lines; `tests/unit/application/test_scanner_size.py` passes unmodified).
- **FR-003 (edge shape unchanged)**: same edge type, direction and attributes as today; no new
  node types, edge types, attributes, config keys, CLI flags or output fields.
- **FR-004 (path preservation)**: US3.1-US3.4 hold on the representative graph.
- **FR-005 (fan-out removed)**: US4.1 and US4.2 hold.
- **FR-006 (semantics documented)**: `EdgeType.ENABLES` in `graph.py` carries a comment stating
  "capability -> vulnerability it is implicated in" and the three tiers; the `enables` row of
  `docs/concepts/knowledge-graph.md` (today "One capability enables another", which is wrong) is
  corrected to the same meaning.
- **FR-007 (no regressions)**: existing graph, report, structure-import, scanner, result-builder
  and `ToolChainAnalyzer` tests pass unmodified; no new dependency; `uv.lock` unchanged; no UI,
  report or report-cap change.

### Assumptions (recorded, most conservative reading)
- **"Keep the attack paths found today" is read as "keep every vulnerability reachable and every
  path whose final capability is implicated"**. A literal "identical path set" is impossible: the
  removed edges *are* one-hop paths. Each removed path is justified by the attack's own tool
  evidence (Edge Cases), and the one class no rule reproduces is kept (tier 3).
- **Source of tool evidence**: `evidence["side_effects"]["tools_invoked"]`, the names already
  extracted from `evidence["tool_calls"]` by `get_side_effect_summary` on both success paths. No
  second parser. `observe_tool_call` records are only visible through `response.tool_calls`; the
  application never reads the adapters' private observation lists.
- **"Capabilities the vector targets" is not available**: `AttackVector` has no
  target-capability field (only `tags`, `category`, `owasp_mapping`, ...). Adding one is a vector
  schema change, out of scope; recorded as a follow-up.
- **Exact-name matching only**: tool name equals capability id or name. No case folding, no
  `canonical_tool_name` aliasing, no prefix stripping (`tool_<name>` ids match via `data["name"]`).
- **Tier 1 does not add dangerous capabilities**: when the attack names the tools it used, those
  are the implicated ones; a dangerous but unused tool is still reachable through its own
  `sensitive_data` path.

### Follow-ups (not in this feature; no issue created)
- An optional `target_capabilities` field on `AttackVector` would let tier 1 apply to findings
  with no tool calls.
- A per-edge `basis` attribute (`tool_call` / `dangerous` / `all`) for the UI, if reviewers want to
  see why an edge exists.

### Key Entities
- **ENABLES edge**: `capability -> vulnerability`, attributes `{"phase": str}`; meaning: the
  capability is implicated in that vulnerability (FR-001).

## Success Criteria *(mandatory)*

### Measurable Outcomes
- **SC-001**: US1-US4 pass as unit tests (`@pytest.mark.unit`) with in-memory graphs and
  `MockAgentAdapter`; no network, no LLM, no keys.
- **SC-002**: on the US4.1 graph the `ENABLES` count is 25 (legacy 200); on the US4.2 scan it
  equals the vulnerability count (legacy 6x).
- **SC-003**: the path regression test proves no endpoint is lost and every dropped path ends in
  a non-implicated capability.
- **SC-004**: all gates pass: `uv run ruff check .`, `uv run ruff format --check .`,
  `uv run mypy ziran/`, `uv run pytest --cov=ziran` (>= 85%).
- **SC-005 (unverified offline)**: the reduction on real customer graphs (and the resulting web UI
  payload size) depends on how often real agents report tool calls; it cannot be measured without
  live targets and is not claimed beyond the mock-adapter numbers.
