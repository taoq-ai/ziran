# Feature Specification: hop-tagged canaries that show how far an injection spreads

**Feature Branch**: `feat/122-hop-propagation`
**Created**: 2026-11-26
**Status**: Draft
**Input**: plan item F-PROPAGATION. `MultiAgentScanner._run_cross_agent_campaign` runs the
multi-agent vectors through the entry agent only and judges them on its reply text. Nothing
records which agent a payload reached, through which tool call, or how many hops away.

## The item in my words

1. Each multi-agent vector (`category: multi_agent`) is planted once at every agent the scan has
   an adapter for. The planted prompt is the vector's own first prompt with a canary appended.
   The canary carries the hop it was planted at (its delegation distance from the entry agent)
   and a hash of the campaign, vector and agent, so each plant has its own marker.
2. After each plant, every adapter reports where the canary appeared, through `get_state()`:
   the indexes of its `conversation_history` entries that hold it, and its tool calls (the
   `observed_tool_calls` list in `memory`, plus the planted agent's own reply calls) whose
   arguments hold it. Tool-call evidence uses the side-effect goal judge (spec 116) with a
   `canary_egress` goal over the calls' own tools, so each call carries its turn, place, tool and
   argument path.
3. The trace gives the path through the discovered topology from the planted agent to the
   furthest agent the canary reached, the furthest hop, and each reached agent's evidence. An
   agent whose adapter failed to report is listed as unobserved, never as clean; a plant whose
   invoke failed records the error and reaches nothing (unmeasured).
4. The planted agent's reply is matched against the known topology of the other agents: their
   ids and names, their capabilities, and sentences of their known system prompts. Each match is
   recorded as a leaked part against the agent it belongs to.
5. Each path step is drawn in the knowledge graph as a `propagates_to` edge between agent nodes.
   The campaign summary and `ziran multi-agent-scan` report the furthest hop and each spreading
   trace; the CLI writes every trace to `propagation.json`.
6. No new attack payload: the vectors and their text are unchanged. Requests made inside a plant
   carry probe markers (spec 117) when the adapter sets them, recorded on the trace.

**Acceptance (the item's).**

- Given a supervisor with two workers, when `ma_cross_agent_injection` runs and the canary
  appears in worker B's tool call, then the finding names entry to A to B with each hop's
  evidence.
- Given the same topology, when a MASLeak-style query returns the workers' system prompts, then
  `ma_topology_exfil` records the extracted parts against the known topology.

In my words, as tests on the real `MultiAgentScanner` with in-process fake adapters:

- The supervisor hands every message to worker A, A to worker B, and B calls `file_ticket` with
  the message. The `ma_cross_agent_injection` trace planted at the supervisor has path
  supervisor, worker A, worker B, furthest hop 2; A's evidence is a history message and B's is
  the `file_ticket` call with argument path `$.body`. The graph holds the two `propagates_to`
  edges.
- The supervisor answers the `ma_topology_exfil` prompt with both workers' system prompts. The
  trace's leaked parts include a `system_prompt` part for each worker and their names.

## Requirements

- **FR-001** `hop_canary(campaign_id, vector_id, agent_id, hop)` returns
  `ZIRAN-H<hop>-<10 hex>`; `X` replaces the hop for an agent off the topology.
- **FR-002** The path to an agent is the shortest directed delegation path (bidirectional edges
  count both ways) through agents that saw the canary when one exists, otherwise through the
  whole topology. Its hop is that path's length; an agent with no path has hop `null`. The
  planted hop is the same distance from the entry agent.
- **FR-003** Every adapter is reset before each plant, so evidence belongs to that plant.
- **FR-004** `run_multi_agent_campaign(trace_hops=True)` runs the tracing after the cross-agent
  campaign; `trace_hops=False` skips it.
- **FR-006** Tracing fails closed (review round 1). Only an adapter whose
  `observes_delegated_traffic` is true (new `BaseAgentAdapter` property, default false) is read
  for agents other than the planted one. Every other adapter, and every topology agent without
  an adapter, is listed as unobserved. The summary's `beyond_hop_0` is `unmeasured` when no plant
  had another agent able to report, and the CLI prints "unmeasured beyond hop 0".
- **FR-007** A reset that raises makes that plant an unmeasured trace (`error: reset <agent>:
  ...`), never a lost campaign. Tool calls are read from `observed_tool_calls`, else the HTTP
  adapter's `tool_observations`, else the planted agent's reply calls.
- **FR-008** Leak precision: a capability counts only when identifier-shaped (5 or more
  characters with `_`, `-`, `.`, a digit or camelCase); a system-prompt sentence shared by two
  agents, or in a short boilerplate list, does not count.
- **FR-009** Cost: each reply's target tokens go on the campaign budget's ledger (spec 047);
  once `max_campaign_tokens` or `max_cost` is reached, the remaining plants are skipped as
  unmeasured. `ziran multi-agent-scan --no-trace-hops` skips the stage.
- **FR-005** No change to detectors, the hybrid judge, role typing, tool aliases,
  `chain_patterns.yaml` or any vector file.

## Assumptions

- The adapter key of the entry agent maps to `topology.entry_point_id` (the discoverer names it
  `entry_agent`); other adapter keys are topology agent ids, as the discoverer builds them. Would
  change if topology ids diverge from adapter keys.
- Hop order is not inferred from timing. When the topology has a shorter edge than the one the
  canary may have taken, the shorter path is reported (a lower bound). Overturned if adapters
  start reporting the sender of each message.
- Only `get_state()` is read; the one interface change is the defaulted
  `observes_delegated_traffic` property, which no shipped adapter sets yet. So every shipped
  adapter reads unmeasured beyond hop 0 until it observes delegated traffic and says so.
- Planting at every adapter costs one request per vector per agent (11 vectors in the `multi_agent` category today), run one
  at a time because each plant resets shared state.
