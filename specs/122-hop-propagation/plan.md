# Implementation Plan: hop-tagged canaries

**Branch**: `feat/122-hop-propagation` | **Spec**: [spec.md](spec.md)

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13). Pydantic v2, NetworkX (already a dependency), stdlib
`hashlib`/`re`. No new dependency, no new attack payload, no vector file change.

## Approach

1. `ziran/domain/entities/multi_agent.py`: `HopEvidence` (agent, hop, history indexes, tool
   calls as `GoalCall`), `LeakedPart` (agent, kind, text) and `PropagationTrace` (vector,
   planted agent and hop, canary, reached, path, furthest hop, leaked, unobserved, probe
   markers, error).
2. `ziran/application/multi_agent/propagation.py` (new, so `scanner.py` stays small):
   - `hop_canary` hashes campaign, vector and agent and carries the planted hop.
   - `trace_propagation` plants each vector's first prompt (rendered by
     `AttackExecutor._render_prompt`) plus the canary at every adapter, one at a time, after
     resetting every adapter, inside `probe_scope` (spec 117).
   - `_observe` reads each adapter's `get_state()`: history entries holding the canary, and the
     tool calls in `memory["observed_tool_calls"]` judged by `goal_status` with a
     `canary_egress` goal over the calls' own tools (spec 116).
   - `_path` takes the shortest delegation path through agents that saw the canary, else
     through the topology.
   - `_leaks` matches the planted agent's reply against the other agents' ids, names,
     capabilities and system-prompt sentences of four words or more.
3. `MultiAgentScanner.run_multi_agent_campaign(trace_hops=True)` runs it after the cross-agent
   campaign on the `multi_agent` vectors, adds a `propagates_to` edge per path step
   (`EdgeType.PROPAGATES_TO`), and returns the traces on `MultiAgentCampaignResult.propagation`;
   `summary()` gains a `propagation` block.
4. `ziran multi-agent-scan` prints the furthest canary hop and writes `propagation.json`.
5. `docs/concepts/multi-agent.md`: a "Stage 4: Hop Tracing" section.

## Freeze check

No file under `ziran/application/detectors/`, `ziran/application/hybrid/`, role typing, tool
aliases, `chain_patterns.yaml` or any vector YAML changes. `call_name` and `goal_status` are
imported, not edited.
