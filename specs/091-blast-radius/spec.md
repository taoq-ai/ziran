# Feature Specification: blast radius per chain, demonstrated vs reachable, with what-if

**Feature Branch**: `feat/091-blast-radius`
**Created**: 2026-11-23
**Status**: Active
**Plan item**: A-BLAST-RADIUS (goal G-a), issue #541, slice 1 of 2. Slice 2
(A-BLAST-RADIUS-REPORT) adds data tags, the Markdown and HTML sections and SARIF properties.
**Base**: `develop` @ 7006a23 (specs 086 and 088 merged).

## The promise in our own words

A finding's `business_impact` comes from its attack category and severity alone, so two agents
with the same category get the same impact whatever they can reach. A reader cannot tell what an
attacker gets once a chain is exploited.

After this change:

1. `ziran/application/knowledge_graph/blast_radius.py` gives
   `blast_radius(graph, start_tool_ids, *, remove=(), tool_calls=(), external=None)`. From the
   start tools, and the agents that hold them through `USES_TOOL`, it walks `USES_TOOL`,
   `ACCESSES_DATA`, `DELEGATES_TO`, `CAN_CHAIN_TO` and `SHARES_CONTEXT` edges forward. It lists
   the data sources reached, the tools whose `role_typing.tool_roles` include `exec`, `egress` or
   `high_impact`, the agents reached downstream, and the outbound channels (`external`).
2. Co-resident `CAN_CHAIN_TO` edges (spec 086) count: one model holds those tools, so each
   reaches the others. This is the one walker beside the pair rule that reads them; the bound is
   below.
3. Each node is `demonstrated` when the campaign's recorded tool calls touched it, else
   `reachable`. The two lists never share a node. A tool is touched when a call named it; a data
   source when a called tool has an `ACCESSES_DATA` edge to it; an agent when it holds a called
   tool.
4. An egress tool that reaches parties outside the organisation (mail, public HTTP, messaging) is
   also listed as `external`: a sending tool (the trifecta's egress leg, so `read_email` is not
   one) whose name holds a mail, HTTP or messaging word. A per-tool override maps a tool id, or
   its name without `tool_`, to `true` or `false`, the way trifecta and role overrides do.
5. `remove=[tool_ids]` previews a fix: the walk skips those nodes. The input graph is never
   changed.
6. `DangerousChain.blast_radius` (optional, default `None`) holds a `BlastRadius`
   (`demonstrated` and `reachable`, each a `BlastReach`). `ResultBuilder` fills it for each chain
   from the chain's last tool, matching demonstrated against the `tool_calls` in every
   `AttackResult.evidence`.
7. The scan JSON carries the radii once per last tool, in `CampaignResult.blast_radius`
   (`{tool_id: radius}`); a chain's radius is `blast_radius[chain["tools"][-1]]`. The chain
   dicts in `dangerous_tool_chains` do not repeat it (see the bound).

## Bound

The target decides how many tools it lists and what it calls them (spec 086, CWE-400, CWE-770).
At the co-resident cap, 100 tools give about 2,500 chains, and every chain in one co-resident set
reaches the same nodes. A radius copied into each chain grew a 6.0 MB result to 28.0 MB. So:

- each list keeps at most `MAX_LISTED = 10` ids, sorted; `counts` gives each list's full size;
- the result JSON keeps one radius per distinct last tool, so the radius output is at most the
  tool count times 12 lists of 10 ids: linear in the tool count and the id length;
- `ResultBuilder` walks once per distinct last tool; each walk visits each edge once.

Measured (`git archive` copies of base 7006a23 and the head, `SETUPTOOLS_SCM_PRETEND_VERSION`
pinned, `timeout -s KILL 300`, flat agents whose tools mix read, HTTP, mail, exec and delete
names, three recorded calls):

| Tools x id length | Chains | Result JSON base -> head | Radii | `build` base -> head |
|---|---|---|---|---|
| 10 x 20 | 29 | 0.03 -> 0.04 MB | 0.01 MB | 0.01 -> 0.01 s |
| 100 x 20 | 2,534 | 2.35 -> 2.51 MB | 0.16 MB | 0.32 -> 0.43 s |
| 100 x 180 | 2,534 | 6.04 -> 6.63 MB | 0.60 MB | 0.49 -> 0.70 s |
| 101 x 180 (over the cap) | 1 | 0.04 -> 0.04 MB | 0.00 MB | 0.06 -> 0.03 s |
| 100 x 20,000 (over the id cap) | 1 | 3.95 -> 4.01 MB | 0.06 MB | 0.81 -> 0.59 s |
| 101 x 20,000 | 1 | 3.99 -> 4.05 MB | 0.06 MB | 0.65 -> 0.61 s |

A `networkx.restricted_view` for `remove` made the walk at 100 tools 1.8 s; the walk skips
removed nodes instead.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A scan shows what a chain reaches (Priority: P1)

1. **Given** a flat agent with `read_file` and `http_request` and a campaign whose tool calls
   include `read_file` on a file and `http_request` to a public URL, **When** the result is
   built, **Then** the `data_exfiltration` chain's `blast_radius` lists the file source as
   demonstrated and `http_request` as egress, demonstrated and external.
2. **Given** a chain whose tools no campaign call touched, **When** the result is built, **Then**
   every entry is reachable and none demonstrated.
3. **Given** malformed recorded calls (a string, `None`, a `function` that is not a dict),
   **Then** they are skipped and the well-formed calls still count.

### User Story 2 - What-if before a retest (Priority: P1)

1. **Given** that graph, **When** `blast_radius` runs with `remove=['tool_http_request']` from
   either tool, **Then** the egress and external parts are empty and the input graph is
   unchanged; a second run without `remove` gives the first radius again.

### User Story 3 - Delegation spreads the radius (Priority: P1)

1. **Given** agent A delegating to agent B, which holds `send_email`, **When** `blast_radius`
   runs from A's tool, **Then** B is a downstream agent and `send_email` is reachable egress
   marked external; B's `upload_report` is egress but not external.
2. **Given** agent C delegating to A, **Then** C and its tools are not in A's radius, and nothing
   flows back from B to A.
3. **Given** a `SHARES_CONTEXT` edge from B to C, **Then** C is reached; a `TRUST_BOUNDARY` edge
   alone reaches nothing.

### User Story 4 - Budgets hold (Priority: P1)

1. **Given** the PR head, **When** `tests/unit/application/test_scanner_size.py` runs, **Then**
   every module stays within budget (`result_builder.py` 196 of 400; `scanner.py` unchanged).
2. **Given** 100 co-resident tools with 180-character ids, 101 tools, and 100 tools with
   20,000-character ids, **Then** every list holds at most 10 ids, no chain dict repeats a
   radius, and the radii JSON stays under 12 x 10 x the summed id length plus 2,000 bytes a tool.

### Edge Cases

- A start tool listed in `remove`, or not in the graph, reaches nothing.
- An unknown id in `remove` changes nothing.
- An override that is not a bool raises `ValueError`.
- A chain with no tools gets no radius.

## Requirements *(mandatory)*

- **FR-001**: `blast_radius` walks the five edge types forward from the start tools and their
  holding agents, on the full graph.
- **FR-002**: Each node is demonstrated or reachable, never both.
- **FR-003**: `is_external` marks outbound channels by name rules, with a per-tool bool override.
- **FR-004**: `remove` skips nodes; the input graph is never changed.
- **FR-005**: `DangerousChain.blast_radius`, filled by `ResultBuilder`; `CampaignResult.blast_radius`
  keeps one radius per last tool.
- **FR-006**: Lists are capped at `MAX_LISTED` with full `counts`.

## Success Criteria

- The acceptance scenarios above pass; the ground-truth benchmark components are unchanged.

## Assumptions

- The walk starts at the agents that hold the start tools as well as the tools: without it a
  tool would never reach its agent's delegates (`USES_TOOL` points from agent to tool). Only the
  start tools climb to their agents, so a tool shared by two agents does not pull in the second
  agent once reached through the first. Overturned if a graph gains tool-to-agent edges.
- The holding agents are not listed as downstream agents: they are where the attack starts.
- "Outbound channels" are the `external` list, a subset of egress plus any tool an override
  marks external. Overturned if slice 2 needs channels as their own nodes.
- The `external` override is a function argument only; reading it from `.ziran/` config lands
  with the data tags config in slice 2.
- `remove` skips nodes instead of copying the graph: the same result, no mutation, and four
  times faster than a filtered view.
- The result JSON keeps the radius once per last tool, not in each chain dict, to keep the
  output linear (measured above). In memory each chain still carries it. Overturned if a
  consumer needs the radius inline in a chain dict and accepts the size.
- A trifecta chain's last tool is its last witness tool; its radius is that tool's.

## How this fails

1. A graph-shaped agent whose tools only link through shared state: the walk follows
   `ACCESSES_DATA` through the state node, so readers of a written channel are reached. A
   channel a tool only reads from leads nowhere, which is right.
2. A name the rules misjudge as external, or miss: the override corrects it per tool, and the
   `reachable` versus `demonstrated` split is unaffected.
3. A target listing thousands of tools without co-resident edges: the walk is linear in edges
   and the output fixed per last tool, so the cost follows the graph the scan already built.
