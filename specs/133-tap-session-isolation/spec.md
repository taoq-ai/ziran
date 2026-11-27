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

- **FR-001**: A TAP vector on an adapter that declares `isolates_sessions` (its reset gives a
  fresh session on the target's side; default False) and not `memory_persists_across_reset`
  calls `reset_state()` before each node and replays the node's ancestors' prompts, in order,
  before the node's own prompt. `evidence.campaign.session` is `isolated`.
- **FR-002**: On any other adapter TAP sends each node once into the shared session, with no
  reset, and records `session: shared`. `isolates_sessions` is True for the Anthropic, OpenAI
  Agents, LangGraph, AutoGen and Bedrock adapters, and False for HTTP, browser (its reset clears
  only ziran's lists), LangChain, CrewAI and AgentCore.
- **FR-003** (fix round 1, planner decision): in an isolated tree the goal is checked after each
  node on that node's branch only (its answered ancestors and itself), and the final
  `judge_goal` sees the deciding node's branch, else the chosen node's. In a shared session the
  goal is judged on every answered node, as one conversation, as merged and as live crescendo.
- **FR-004**: Replayed calls count as the vector's target tokens and as running budget tokens.
  The cap is checked before each node's attacker call and after each replay, so at most one
  target call per node (its first, as the merged node call) starts past the cap; the campaign
  then stops with `budget`.
- **FR-005**: A replay that raises or returns an error sentinel gives the node no reply (a
  prompt error, `pruned: no_reply`).
- **FR-006**: A node's reset, replay and prompt run under an exclusive hold of the adapter's
  session gate, and every multi-turn tactic run now takes a shared hold, so a node's reset never
  lands inside a gated conversation and no gated turn lands inside a node's session.
- **FR-007**: Live crescendo, PAIR, the cassette and trials behave as merged.

## How this fails

1. An adapter that declares `isolates_sessions` but whose target keeps state across a new
   session id reads as `isolated` while siblings still share memory.
2. PAIR and single-prompt vectors take no gate, so one running at the same time can land a turn
   inside a node's session, or have its history cleared by a node's reset.
3. Replays multiply target cost: a node at depth d costs d target calls, so a tree reaches the
   cap sooner and has fewer nodes than before under the same budget.

## Assumptions

- "Can reset" is an explicit adapter property, `isolates_sessions` (fix round 1: the browser
  adapter's reset clears only local lists). An unknown adapter is shared and says so. No adapter
  exposes a fork. Overturned per adapter when its reset is shown to give a fresh target session.
- A branch's goal is judged on the turns recorded when its nodes first ran, not on the replayed
  replies, so goal evidence turns keep naming nodes. Overturned if a replay's calls must count.
- Concurrent PAIR and single-prompt vectors stay ungated, as today (failure 2 above); the phase already
  runs attacker vectors after every other vector starts.
- A replay repeats an ancestor's tool calls on the target (side effects included); the replays'
  replies and calls are not recorded or judged.
