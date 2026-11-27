# Feature Specification: attacker-LLM campaigns (TAP tree search, live crescendo)

**Feature Branch**: `feat/128-attacker-loop`
**Created**: 2026-11-27
**Status**: Draft
**Input**: plan item F-ATTACKER-LOOP (goal G-f, tier full). Builds on PAIR (spec 081), the
campaign budget (spec 047), the side-effect goals (specs 116, 124) and the record-replay seam
(spec 064).

## The item in my words

PAIR lets an attacker LLM rewrite one prompt, one stream, until the target complies. Two
stronger shapes of the same loop are common in red-team tools: a live multi-turn conversation in
which the attacker writes each next user turn from the replies so far (crescendo, run by an
attacker rather than a script), and a tree search in which each prompt branches into several
refinements, the best few are kept at each level and the rest are pruned (TAP). A
`CampaignExecutor` runs both, and PAIR as its third mode, through the same attacker client
(`BaseLLMClient`), the same target call and detector verdict, and the same `CampaignBudget`. A
vector chooses the mode with its `tactic` (`tap`, `crescendo_live`, `pair`) and bounds it with a
`campaign` block. The run stops when the vector's goal is met (or, with no goal, on a text
success), at the budget, or at a bound, and the result's evidence holds the tree: every node's
prompt, reply, score and pruning reason, and the edges between them. Node ids come from the
node's place in the tree, so a repeat with the same attacker replies and the same target gives
the same tree.

No CLI flag is added: the attacker client comes from the Python API today and from
`ziran scan --attacker-model` once F-SCAN-ATTACKER-FLAG lands; that flag drops attacker vectors
by `is_pair`, which covers the new tactics.

**Acceptance, in my words.**

1. A TAP vector with a goal (a shell sink with a canary, the example scenario
   `campaign_tap_shell_canary` in `examples/30-attacker-campaigns/`) runs under a 50,000-token
   campaign budget against a scripted target with a shell tool, driven by a fake attacker. It
   stops on `goal_met` or at the budget, and the evidence lists every node with its prompt,
   reply, score and pruning reason. Under a budget too small for the goal, it stops at the
   budget with the tree so far.
2. Run 1 records the attacker's replies in a spec 064 outcomes file. Run 2 replays them through
   `RecordReplayClient` against the same scripted target with no live attacker, and its tree
   equals run 1's.

## How this fails

1. **A loop that does not end.** A tree grows as width times branching per level, and a
   conversation as turns. Every loop has a bound in the vector (`width`, `branching`, `depth`,
   `turns`, `max_nodes`), each capped by the model, plus the campaign budget checked before every
   attacker call and the vector's deadline. Each bound has a test that stops on it.
2. **A tree that differs on replay.** A node id taken from a counter shared across tasks, a set
   order, or a request that does not name the node makes the same replies land on other nodes.
   Ids are the node's path (`2.1` is the first child of `2`), every attacker request names its
   node, and ties in pruning break on the node's order of creation.
3. **A goal met but not seen.** If the executor stops on the text verdict only, an agent that
   runs the payload without saying so reads as a failure, or a run continues past a met goal and
   spends the budget. The executor asks `goal_status` after each answered node, with the same
   turn keys `judge_goal` reads at the end, so the stop and the final `goal_met` agree.

## Requirements

- **FR-001** `AttackVector.tactic` accepts `tap` and `crescendo_live`. Both, like `pair`, need an
  attacker client; `is_pair` is true for all three, so they queue after static vectors, get the
  phase deadline, and are dropped by the not-run rule of F-SCAN-ATTACKER-FLAG.
- **FR-002** A `campaign` block (`CampaignConfig`, extra keys rejected) bounds the run: `width`
  (1 to 10, default 3), `branching` (1 to 5, default 2), `depth` (1 to 10, default 4), `turns`
  (1 to 30, default 8), `max_nodes` (1 to 200, default 40) and `timeout_seconds` (above 0,
  at most 3600, finite, default 600). `PairConfig.timeout_seconds` keeps its range and refuses
  only a non-finite value. It loads from YAML through `AttackLibrary`. A `campaign` block on any other
  tactic is rejected at load.
- **FR-003** TAP: at depth 1 the attacker writes `branching` children of the seed; at each later
  depth it writes `branching` children of each kept node. Each child is one target call and one
  detector verdict. After each depth the answered children are ranked by score (ties by order of
  creation) and the top `width` are kept; the others get `pruned: width`. A node whose target
  call failed or returned no reply gets `pruned: no_reply`. The run stops at `depth`
  (`stop: depth`) or when no node is left to expand (`stop: exhausted`).
- **FR-004** Live crescendo: one conversation with the target. Each turn the attacker sees the
  goal, the turn number and the conversation so far, and writes the next user message. The run
  holds the shared session gate, so a two-session vector's reset never lands inside it. It stops
  after `turns` (`stop: turns`).
- **FR-005** Every mode stops before an attacker call when the campaign budget is exceeded
  (`budget`), counting the target tokens this vector used so far, which the phase books once
  when the vector ends (PAIR too), when `max_nodes` nodes exist (`max_nodes`), or at the deadline (`timeout`); and
  after a node when the vector's goal is met (`goal_met`), or, for a vector with no goal, on a
  text success (`success`). An attacker error stops with `attacker_error`, a pending reply
  (spec 064) with `pending`, each keeping the tree so far. A run that stops on `budget`,
  `timeout`, `attacker_error` or `pending` with no text success is `outcome: unmeasured`, and
  its `goal_met` is `null` (PAIR too): it never reads as resisted.
- **FR-006** A score is 1 for a text success or a met goal, else the quality judge's composite
  (rounded to 4 places), else 0. The tree lands in `evidence.campaign`: `mode`, `stop`,
  `attacker_model`, `attacker_parse_errors`, `nodes` (each with `id`, `parent`, `depth`, `turn`,
  `prompt` up to 2,000 characters, `reply` up to 500, `score`, `pruned`) and `edges` (`from`,
  `to`); the target gets the whole prompt. An attacker reply that is not a JSON object with a
  `prompt`, including one too large or too deeply nested to parse, makes no node and counts as a
  parse error (PAIR too).
- **FR-007** Each answered node's tool calls and text are recorded under its `turn` (its order
  of creation, from 1), so `judge_goal` and `goal_evidence` name the node. The result is
  successful when any node was a text success; it shows the deciding node, else the first text
  success, else the best-scoring node. Attacker tokens go to the ledger under `attacker`.
- **FR-008** A campaign result is never cached by the incremental scan cache.
- **FR-009** PAIR is the third mode: `CampaignExecutor` runs `tactic: pair` through the PAIR loop
  unchanged, and its evidence stays under `pair`.
- **FR-010** No change to detectors, the hybrid judge or its prompts, `review_evidence`, role
  typing, tool aliases, `chain_patterns.yaml` or `study-*` refs; `scanner.py` gains no line; each
  `agent_scanner` and `attacks` module stays at 400 lines or fewer.

## Clarifications

- Q: Does a text success stop a vector that has a goal? A: no. The goal is the stop condition
  when the vector names one; a text success is recorded (the result is successful) and the run
  goes on until the goal is met or a bound. With no goal, a text success stops.
- Q: Is the seed prompt sent? A: no, as in PAIR. The seed is what the attacker refines; every
  node is a prompt the attacker wrote.
- Q: Does TAP reset the target between nodes? A: no, as in PAIR: a reset would cut another
  vector's conversation on a shared adapter. Each node is one more message to the target.
- Q: Does live crescendo backtrack on a refusal? A: no. The attacker sees the refusal and writes
  the next turn. Backtracking needs a reset, which the shared adapter rules out.
- Q: Which turn does a goal's evidence name? A: the node's `turn`, its order of creation.

## Assumptions

- The attacker request is a system message and one user message, as PAIR sends, so a live
  provider client works unchanged. The spec 064 `RecordReplayClient` takes one user message with
  `job`, `unit` and `prompt` keywords, so the replay test adapts the request in a few test lines.
  Why: changing the seam's request shape or the frozen hybrid client is out of bounds. Overturned
  if an offline repeat must run from the CLI, which needs a cassette option (a candidate beside
  `--attacker-model`).
- The offline repeat replays the attacker; the target is the deterministic scripted target. Why:
  the acceptance names a scripted target, and ziran has no general target cassette. A live target
  with randomness gives a different tree whatever the attacker does.
- The example scenarios live in `examples/30-attacker-campaigns/`, not the built-in library.
  Why: a goal names the owner's tool and canary, as in spec 124, and attacker vectors cost 10 to
  100 times a static vector. Overturned if a built-in attacker vector should ship, which would be
  dropped and listed as not run without an attacker.
- The not-run drop for attacker vectors comes from F-SCAN-ATTACKER-FLAG through `is_pair`. Until
  it lands, a `tap` or `crescendo_live` vector without an attacker client is an error row, as a
  `pair` vector is today.
- TAP's first-phase prune (an off-topic check before the target call) is not built: the item
  names pruning by score. Overturned if measured runs show off-topic nodes eating the budget.

## Out of scope

A CLI flag; GOAT's attack-technique library; backtracking; a target cassette; report rendering of
the tree beyond the JSON evidence.
