# Implementation Plan: TAP session isolation

**Branch**: `feat/133-tap-session-isolation` | **Spec**: [spec.md](spec.md)

## Technical Context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13), stdlib `asyncio`; no new dependencies. Touches
`ziran/application/attacks/campaign.py` and two lines of `ziran/application/attacks/tactics.py`.
`scanner.py`, the goal judge, detectors and the spec 064 seam are untouched.

## Constitution Check

Hexagonal: the executor uses only the `BaseAgentAdapter` port (`reset_state`, `invoke`,
`isolates_sessions`, `memory_persists_across_reset`). Type safety: mypy strict. Tests first. No new abstraction.

## Design

1. `BaseAgentAdapter.isolates_sessions` (default False), True on the Anthropic, OpenAI Agents,
   LangGraph, AutoGen and Bedrock adapters. `_Tree.isolated`: true for `tap` when the adapter
   declares it and not `memory_persists_across_reset`.
2. `CampaignExecutor._fresh`: under `_GATES[adapter].hold(exclusive=True)`, `reset_state()`,
   replay the branch's earlier prompts (`tree.sent`), booking each and checking the cap, then
   `_attempt` with those prompts as the conversation's earlier attack text.
3. `_book`: the token booking shared by node calls and replays.
4. `_judged(tree, node, parent)`: in an isolated tree the turns and replies of a node and its
   answered ancestors, else every answered node. `_node` checks the goal on it; `_finish` fills
   the caller's `turns` and `replies` from it for the deciding (else chosen) node.
5. `TacticExecutor.execute` takes the shared gate for every run, not only on targets with memory
   across reset, so a node's exclusive hold waits for in-flight multi-turn conversations.
6. `evidence.campaign.session`: `isolated` or `shared`, TAP only.

## Tests

`tests/unit/test_tap_session_isolation.py`: a stateful agent whose reply is a digest of its
session. Isolated: each node's reply is the digest of its branch prompts, one reset per node,
target calls equal the sum of node depths and every call is booked. Shared: no reset, no replay,
pooled replies. Branch goal: an approval bypass met on node 2 alone while pooled it is not, and a spend threshold met only across node 1 and its child.
Concurrency: a crescendo tactic run beside TAP keeps one uncut session. Fix round 1: a shared
session is judged pooled (60 + 60 siblings meet a 100 threshold; approval then pay is not met);
a replay that raises or returns an error sentinel leaves the node with no reply and never sends
its prompt; a secret leaked in a branch reply meets the goal; replays stop at the cap (ten calls
under 50,000 at 5,000 each); a browser target records `session: shared`.
