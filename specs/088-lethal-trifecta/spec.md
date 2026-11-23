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
- `DetectorThresholds` gains a field, so the incremental scan cache key changes once for scans
  with a detector config. Overturn: none expected.
- A trace alert is fingerprinted by tools and session, so a trifecta over the same tools as a
  pair chain shares its GitHub issue (`test_dangerous_chain_files_one_issue_then_dedups`).
  Overturn: slice 2 wants a separate trifecta issue.
- The trace order rule and the delegated variant are slice 2 (A-TRIFECTA-TRACES); traces get the
  unordered check in this slice.

## Out of scope (slice 2, A-TRIFECTA-TRACES)

The trace order rule (egress after untrusted content in one session), the
`lethal_trifecta_delegated` variant along delegation edges, and ground-truth agents in
`benchmarks/ground_truth/agents/`.
