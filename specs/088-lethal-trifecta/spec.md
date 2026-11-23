# Feature Specification: lethal trifecta check for audit, scan and traces

**Feature Branch**: `feat/088-lethal-trifecta`
**Created**: 2026-11-23
**Status**: Active
**Plan item**: A-TRIFECTA (goal G-a), issue #537, slice 1 of 2.
**Base**: `develop` @ bc179ee (spec 086 merged).

## The promise in our own words

The chain rules describe tool pairs. They cannot say "this one agent reads private data, sees
untrusted content and can send data out". With all three legs, a prompt injection in the
untrusted content can make the agent send the private data to an attacker, whatever order the
tools run in.

After this change:

1. `ziran/application/knowledge_graph/trifecta.py` gives each tool its legs: `private_data`,
   `untrusted_content` and `egress`. The legs come from name rules over `canonical_tool_name`
   and `tokens`, or from a per-tool override. A tool can hold several legs: `WebFetch` is
   untrusted content and egress, `read_inbox` is untrusted content and private data. The egress
   words reuse `role_typing.EGRESS`; the V2 lists in `role_typing.py` are unchanged.
2. `ToolChainAnalyzer.analyze` runs a trifecta step after the shell and typed steps. It reports
   one `DangerousChain` per agent whose tools cover all three legs: `vulnerability_type`
   `lethal_trifecta`, `chain_type` `trifecta`, `risk_level` critical, `evidence` as
   `{leg: [tools]}` (plus `agent` on a graph-shaped agent), and a remediation to remove or
   restrict one leg. `ziran audit`, `ziran scan` and `ziran analyze-traces` all reach it through
   `analyze`, so `scanner.py` gains no line.
3. An agent is all its tools on a flat agent (no `AGENT` node). On a graph-shaped one it is each
   `AGENT` node's `USES_TOOL` tools, plus one scope for the tools no agent lists, as spec 086
   forms its co-resident sets.
4. `ziran audit` reports each one as a `StaticFinding` with the rule id `LT001`, beside `CC001`.
   `CC001` no longer carries it. The scan SARIF (`generate_sarif`, used by `ziran ci`) carries
   the same `LT001` rule and one result per trifecta chain.
5. The audit baseline records the trifecta as a chain. A chain is accepted by its tools and its
   `vulnerability_type`, so a recorded `data_exfiltration` over `Read, WebFetch` does not accept
   a `lethal_trifecta` over the same tools.
6. `trifecta_roles` in `.ziran/detectors.yaml` maps a tool id or name to its legs, in place of
   the name rules (`[]` is no leg). `DetectorThresholds` validates it; the CLI hands it to the
   graph (`AttackKnowledgeGraph.trifecta_roles`) for scan and to `audit_claude_code`,
   `build_baseline` and `apply_baseline` for audit.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - The audit flags a trifecta agent (Priority: P1)

1. **Given** a Claude Code agent with `tools: Read, WebFetch`, **When** `ziran audit` runs,
   **Then** it reports one `LT001` finding that names `Read` as private data and `WebFetch` as
   untrusted content and egress.
2. **Given** an agent with `read_inbox, get_customer, send_email`, **When** the audit runs,
   **Then** it reports one `LT001`; without `send_email` it reports none.

### User Story 2 - The scan flags a flat trifecta agent (Priority: P1)

1. **Given** a flat agent with `read_inbox`, `get_customer` and `send_email`, **When**
   `ziran scan` runs, **Then** `CampaignResult.dangerous_tool_chains` holds one
   `lethal_trifecta` chain and the SARIF output carries `LT001`.
2. **Given** the same agent without `send_email`, **Then** no `lethal_trifecta` chain appears.

### User Story 3 - An operator corrects a tool's legs (Priority: P1)

1. **Given** `trifecta_roles: {send_email: []}` in `.ziran/detectors.yaml`, **When** the audit
   or the scan runs, **Then** no trifecta is raised.

### User Story 4 - A baseline accepts the trifecta (Priority: P1)

1. **Given** a baseline recorded over the researcher agent, **When** the audit runs again with
   it, **Then** no `LT001` or `BL003` row appears: the finding is accepted as baselined.
2. **Given** a baseline that holds only the pair chain over the same tools, **Then** a `BL003`
   row names the `lethal_trifecta`.

### Edge Cases

- One tool with all three legs (an override, or a future name) is a trifecta on its own.
- Two agents with the same tools each get a finding: the analyzer's de-duplication key carries
  the agent.
- `Bash` holds no leg from the name rules: an unscoped `Bash` is already `unrestricted_execution`.
- `WebSearch` (`browse_url`) is untrusted content only: its query goes to the search provider,
  not to a URL the attacker picks.
- An invalid `.ziran/detectors.yaml` warns on stderr and gives no override, so the name rules
  still report every trifecta (fail safe). Audit used not to read the file at all (spec 067).
- Hostile `tools/list`: 100 or 101 tools, ids of 100 or 20,000 characters. The step walks no
  pair or path, so it runs above spec 086's co-resident cap too. The chain's `tools` and
  `graph_path` hold the first tool of each leg, at most three ids, so the finding node id and its
  attack paths stay small; the evidence lists every leg tool once.

## Sizing (measured, `ResultBuilder.build` after `import_adapter_structure`)

Tools are `read_inbox_<i>_x...` plus `send_email`, so every one but the last holds two legs.
Measured on `git archive` copies of base and head; `test_hostile_tool_lists_stay_linear` in
`tests/unit/test_trifecta.py` holds the bound.

| Tools | Id length | Base | Head |
|-------|-----------|------|------|
| 100 (at spec 086's cap) | 100 | 0.04 s, 0 chains | 0.05 s, 1 chain, 0.02 MB |
| 101 (over the cap) | 100 | 0.03 s, 0 chains | 0.03 s, 1 chain, 0.02 MB |
| 102 | 100 | 0.02 s, 0 chains | 0.04 s, 1 chain, 0.02 MB |
| 101 | 20,000 (ids: 1.98 MB) | 0.35 s, 0 chains | 0.57 s, 1 chain, 4.06 MB |

A first cut put every leg tool in `tools`: the last row gave 208 MB, because the finding node
id and each attack path to it copied all of them (tools squared times id length). The head keeps
it linear.

## Walkers

The trifecta step reads node types and each `AGENT` node's out-edges on
`graph.structure_view()` (spec 086's rule), no path or pair. It adds one row to spec 086's walker
table: `trifecta._scopes`, `out_edges` of agent nodes, structure view.

## How this fails

1. A name rule misses a real private data tool (`lookup_order`), so a trifecta goes unreported.
   The override covers it; slice 2 adds ground-truth agents to measure it.
2. A name rule over-reads (`search_docs` as private data), so a benign agent gets a critical
   finding. The override removes it; the baseline accepts it.
3. A hostile tool list blows the output up. Measured above and held by a test at 100 and 101
   tools and 20,000-character names.

## Requirements

- **FR-001** `tool_legs(tool_id, override=None)` returns the legs; a bad override raises
  `ValueError`.
- **FR-002** `ToolChainAnalyzer.analyze` reports one `lethal_trifecta` chain per agent scope
  that covers all three legs, with `graph.trifecta_roles` over the name rules.
- **FR-003** `ziran audit` reports it as `LT001`; `CC001` excludes it.
- **FR-004** `generate_sarif` carries `LT001` for each scan trifecta chain.
- **FR-005** The baseline accepts a chain by tools and `vulnerability_type`.
- **FR-006** `DetectorThresholds.trifecta_roles` validates the override; `ziran audit` and
  `ziran scan` read it.

## Assumptions

- "Reported as baselined" means what the baseline does for `CC001` today: an accepted chain's
  row is dropped and the audit passes. There is no separate "baselined" row. Overturn: the owner
  wants accepted rows shown.
- The `LT001` row's `tools` are the first tool of each leg, not every leg tool; the message and
  the chain's evidence name every leg tool. Overturn: a consumer needs every tool in `tools`.
- Audit sees MCP tools as the `mcp__server__tool` ids an agent lists; it does not start a
  plugin's `.mcp.json` servers to read their `tools/list`. Overturn: the owner wants server
  tools pulled in.
- `trifecta_roles` reaches `ziran scan` and `ziran audit`. The multi-agent scan, the pentest
  agent, the promptfoo provider and `analyze-traces` use the name rules only. Overturn: an
  operator needs the override there.
- `ziran scan` now reads `.ziran/detectors.yaml` for `trifecta_roles` even with no LLM
  backbone, which overturns spec 041's "a scan with no backbone does not use the file". An
  invalid or unreadable file warns on stderr. Overturn: you want such a scan file-free.
- An unreadable or non-UTF-8 `.ziran/detectors.yaml` (a directory, UTF-16) is a
  `DetectorConfigError` in `load_detector_thresholds`, so audit and scan warn instead of crashing.
- Above spec 086's co-resident cap the scan warning still says tool chains "were not analysed",
  though the trifecta step runs there. The text lives in `agent_scanner/structure_import.py`,
  outside this item's files; a follow-up can reword it.
- Two graph agents with the same witness tools give two chains but share one composition node
  (`add_chain_finding` keys by type and tools). Overturn: the node must be per agent.
- In the ground-truth benchmark, `url_allowlist` and `no_network_access` mitigate
  `lethal_trifecta`: both restrict the egress leg. Without that the true negative
  `gt_tc_tn_012` is flagged (scenario verdict FP 3 to 4, precision 91.7% to 89.2%); with it the
  results equal base.
- Existing audit baselines report a `BL003` for each agent that holds the trifecta until they
  are recorded again with `--write-baseline`.
- `DetectorThresholds` gains a field, so the incremental scan cache key changes once for scans
  with a detector config. Overturn: none expected.
- A trace alert is fingerprinted by tools and session, so a trifecta over the same tools as a
  pair chain shares its GitHub issue (`test_dangerous_chain_files_one_issue_then_dedups`).
  Overturn: slice 2 wants a separate trifecta issue.
- The trace order rule and the delegated variant are slice 2 (A-TRIFECTA-TRACES); traces get the
  unordered check in this slice.


# Slice 2: trace order, the delegated variant and ground truth

**Plan item**: A-TRIFECTA-TRACES (goal G-a), issue #537, slice 2 of 2. Closes #537.
**Base**: `develop` @ 7006a23 (slice 1, #543, merged).

## The promise in our own words

1. `ziran analyze-traces` reports a `lethal_trifecta` for a session only when its calls cover
   all three legs *and* some egress call comes after an untrusted content call. A session that
   sends before it reads anything untrusted cannot carry an injection out, so it gets no
   trifecta (its pair chains are unchanged). The finding is the slice 1 chain, with
   `evidence["rule_id"]` set to `LT001`, the same rule id as audit and SARIF.
2. On a graph-shaped agent, when no agent node holds all three legs but an agent's tools plus
   those of the agents it reaches along `DELEGATES_TO` edges do, `ToolChainAnalyzer.analyze`
   reports one `lethal_trifecta_delegated` chain for that delegating agent. Its evidence names
   the agents: `agent` (the delegating one) and `agents` (it, then the first agent in
   delegation order that holds each leg).
3. Two ground-truth agents: `vulnerable_support_inbox` (`read_inbox`, `get_customer`,
   `send_email`) is flagged and `safe_support_inbox` (`read_inbox`, `get_customer`,
   `create_draft`) is clear. Two scenarios (`gt_tc_tp_015`, `gt_tc_tn_013`) put them in
   `benchmarks/ground_truth/run.py`; the PR benchmark gate reads only the vector inventory, so
   its baseline does not change.

## User Scenarios & Testing (slice 2)

### User Story 5 - A trace session in the dangerous order (Priority: P1)

1. **Given** a session `read_inbox`, `get_customer`, `send_email`, **When**
   `ziran analyze-traces` runs, **Then** it reports one `lethal_trifecta` with rule id `LT001`.
2. **Given** a session `send_email`, `read_inbox`, `get_customer`, **Then** no
   `lethal_trifecta` appears.

### User Story 6 - A trifecta split across delegation (Priority: P1)

1. **Given** a topology where `reader` holds `read_inbox` and `get_customer` and delegates to
   `mailer`, which holds `send_email`, **When** the scan imports it, **Then** one
   `lethal_trifecta_delegated` chain names `reader` and `mailer`.
2. **Given** the same agents with no delegation edge, **Then** none appears.

### User Story 7 - Ground truth for both outcomes (Priority: P2)

1. **Given** the two new agents, **When** `benchmarks/ground_truth/run.py` runs, **Then** the
   chain analyzer finds the trifecta on the vulnerable one and nothing on the safe one, and the
   scenario verdict counts one more TP and no new FP.

### Edge cases (slice 2)

- A tool with both untrusted content and egress (`WebFetch`) called once is not in order: its
  request goes out before its content comes in. A second call after it is.
- A session of one call has no order; the analyzer already skips it.
- An agent that holds all three legs itself gets `lethal_trifecta`, not the delegated one. An
  agent that reaches one that does gets no delegated finding either: that agent's finding covers
  it.
- Delegation cycles and self-loops: each agent is visited once per walk.
- Hostile input: many agents in a delegation chain, many tools, long ids, long traces. Measured
  below.

## Walkers (slice 2)

`trifecta._delegated` reads each agent node's `DELEGATES_TO` out-edges on
`graph.structure_view()`, one breadth-first walk per agent, no tool pair or path. The trace
order rule is one pass over the session's calls.

The delegated walk costs O(agents x reachable agents): each agent walks its own reach. Measured
in the security gate on `analyze`, base to head: a ring of 2,000 agents 8.11 to 13.59 s, a chain
of 2,000 4.82 to 7.45 s, a star of 3,000 leaves with back edges 15.45 to 32.65 s, a complete
digraph of 300 agents (89,700 edges) 0.77 to 4.59 s. The base is already super-linear there
(centrality). With 101 agents of 20,000-character ids (4.04 MB), a ring gives 24.34 MB and a
star 22.52 MB of chains: the output stays linear. Topologies come only from in-process adapters
running the operator's own code, so a remote target cannot set this size.

## Sizing (slice 2, measured on head)

`ToolChainAnalyzer.analyze` after `import_adapter_structure` for delegation, and
`AnalyzerService.analyze_sessions` for traces, on `git archive` copies of base (7006a23) and
head. Delegation: agents `a0 -> a1 -> ... -> mailer`, each reader holding one
`read_inbox_<i>_x...` tool and the mailer 101 `send_email_<i>_x...` tools, so every reader
reaches the mailer. The bound is held by
`test_hostile_delegation_chain_stays_linear` and `test_long_trace_stays_linear`.

| Input | Base | Head |
|-------|------|------|
| 101 agents, ids of 100 chars | 0.06 s, 0 chains | 0.07 s, 101 delegated, 0.15 MB |
| 101 agents, ids of 20,000 chars (ids: 4.04 MB) | 1.18 s, 0 chains | 1.19 s, 101 delegated, 14.22 MB |
| 1,000 agents, ids of 100 chars | 1.22 s, 0 chains | 1.74 s, 1,000 delegated, 1.52 MB |
| trace, 10,001 calls over 3 tools, ids of 100 chars | 0.04 s, 1 trifecta, 1.03 MB | 0.05 s, 1 trifecta, 1.03 MB |
| trace, 10,001 calls over 3 tools, ids of 20,000 chars | 3.89 s, 200.17 MB | 3.87 s, 200.17 MB |
| trace, 201 calls over 201 tools | 0.06 s, 1 trifecta | 0.06 s, 1 trifecta |

Each delegated chain holds at most seven ids (three tools, the path, one per leg in the
evidence) and four agent ids, so the output grows with the agents, never with the tools a
shared delegate holds. The 200 MB trace output is the base's `discovered_capabilities`, which
copies every call's tool name; it is unchanged here.

## How this fails (slice 2)

1. The order rule hides a real attack: the trace drops or reorders spans, so the egress call
   looks first. The scan and audit still report the unordered trifecta for that agent.
2. The delegated variant over-reports: a router that only forwards a task name, not data, gets
   a critical finding. The override and the baseline handle it, as for slice 1.
3. A deep or wide delegation graph makes the walk quadratic in agents. Measured above; the
   output per finding stays at four agents and three tools.

## Requirements (slice 2)

- **FR-007** `egress_after_untrusted(calls, overrides=None)` is true when an egress call comes
  after an untrusted content call; `AnalyzerService` drops a session's `lethal_trifecta` when
  it is false and stamps `rule_id` `LT001` on the one it keeps.
- **FR-008** `find_trifectas` adds one `lethal_trifecta_delegated` chain per agent node that
  misses a leg, reaches no agent holding all three, and covers all three with the agents it
  reaches along `DELEGATES_TO`.
- **FR-009** Ground-truth agents and scenarios for both outcomes.

## Assumptions (slice 2)

- "After" is a strictly later call in the session's order (the ingestor's span order). Overturn:
  the owner wants one call with both legs to count.
- The trace order rule applies only to `lethal_trifecta`; pair chains in traces keep their
  existing rules. `test_dangerous_chain_files_one_issue_then_dedups` (`read_file`,
  `http_request`) changes: `http_request` is untrusted content and egress in one call, so no
  trifecta is raised and the re-run dedups one finding, not two.
- `lethal_trifecta_delegated` is critical, like `lethal_trifecta`: the private data can reach
  the egress tool through the delegation. Overturn: the owner wants it high.
- The delegated chain does not reach the scan SARIF, the audit or the baseline in this slice:
  `sarif.py` keys `LT001` on `lethal_trifecta`, and audit agents have no delegation edges. It
  shows in `dangerous_tool_chains`. A follow-up can add it to the SARIF `LT001` results.
  Overturn: the owner wants it in SARIF now. Superseded by spec 092: the scan SARIF carries it
  under `LT002`.
- The two scenarios sit beside the two agents because `run.py` reads an agent only through a
  scenario.
- The vulnerable agent lists `CVE-2025-32711` (prompt injection through a read email), which
  the skill CVE matcher finds on it; without it the matcher scores that match as a false
  positive on an agent with no known vulnerability. The `prompt_injection` type makes it a
  pentest-eval target (LLM01) in `--targets all`, with no cassette (a coverage gap, not a
  failure). The pentest-eval CI gate runs the fixed subset, so its result does not change.
  Overturn: the owner wants a recorded cassette for it.
- `analyze-traces` reads no `trifecta_roles` override (unchanged from slice 1).
