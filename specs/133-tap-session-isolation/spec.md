# Feature Specification: TAP gives each branch its own target session

**Feature Branch**: `feat/133-tap-session-isolation`
**Created**: 2026-11-27
**Status**: Draft
**Input**: plan item F-TAP-SESSION-ISOLATION (goal G-f, tier standard). Follows spec 128 (campaign
executor), spec 131 (shared budget) and spec 132 (attacker cassette). Goal gate on #603, probe P4:
TAP sent 18 nodes into one target session with 0 resets.

## The item in my words

A TAP tree sends every node to the same target session today, so a stateful agent answers a node
with its siblings' and cousins' prompts still in context. Sibling branches are then not
independent, and a goal can be met only by pooling turns across branches. Where a reset gives a
fresh session, each node now resets, replays its own branch's earlier prompts and then sends its
prompt, so its reply depends only on its branch. Where it does not, the shared session stays and
`evidence.campaign.session` says `shared`. Goals are judged on one branch, never pooled across
siblings, and a met goal names its branch's turns.

**Acceptance.** Given a stateful scripted agent and an adapter that resets sessions, when TAP
runs, then each node's reply depends only on its own branch's prompts.

## Requirements

- **FR-001**: A TAP vector on an adapter that does not declare `memory_persists_across_reset`
  calls `reset_state()` before each node and replays the node's ancestors' prompts, in order,
  before the node's own prompt. `evidence.campaign.session` is `isolated`.
- **FR-002**: On an adapter that declares `memory_persists_across_reset`, TAP sends each node
  once into the shared session, with no reset, and records `session: shared`.
- **FR-003**: The goal is checked after each node on that node's branch only (its answered
  ancestors and itself). The final `judge_goal` sees the deciding node's branch, else the chosen
  node's; live crescendo is one branch, so it is judged on the whole conversation as before.
- **FR-004**: Replayed calls count as the vector's target tokens and as running budget tokens.
  No replay starts once the cap is reached: the campaign stops with `budget`.
- **FR-005**: A replay that raises or returns an error sentinel gives the node no reply (a
  prompt error, `pruned: no_reply`).
- **FR-006**: A node's reset, replay and prompt run under an exclusive hold of the adapter's
  session gate, and every multi-turn tactic run now takes a shared hold, so a node's reset never
  lands inside a gated conversation and no gated turn lands inside a node's session.
- **FR-007**: Live crescendo, PAIR, the cassette and trials behave as merged.

## How this fails

1. A target whose `reset_state()` does not reset its own side (a browser chat that keeps the
   thread) reads as `isolated` while siblings still share memory.
2. Single-prompt vectors take no gate, so one running at the same time can land a turn inside a
   node's session, or have its history cleared by a node's reset.
3. Replays multiply target cost: a node at depth d costs d target calls, so a tree reaches the
   cap sooner and has fewer nodes than before under the same budget.

## Assumptions

- "Can reset" is read from the existing control: `reset_state()` gives a fresh session unless the
  adapter declares `memory_persists_across_reset` (spec 113), the flag that says the target keeps
  memory across a reset. No adapter exposes a fork. Overturned by an adapter that needs its own
  isolation flag.
- A branch's goal is judged on the turns recorded when its nodes first ran, not on the replayed
  replies, so goal evidence turns keep naming nodes. Overturned if a replay's calls must count.
- Concurrent single-prompt vectors stay ungated, as today (failure 2 above); the phase already
  runs attacker vectors after every other vector starts.
- The budget check between replays is stricter than one check per node: the merged budget test
  that stopped after node 2.1 now stops before 2.1's own prompt, since 2.1's replay is the last
  call under the cap.
