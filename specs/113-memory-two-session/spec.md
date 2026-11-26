# Feature Specification: two-session memory poisoning (plant, new session, trigger)

**Feature Branch**: `feat/113-memory-two-session`
**Created**: 2026-11-26
**Status**: Active

## The promise in our own words

`mp_cross_session_persistence` (`memory_poisoning.yaml`) sends one prompt and reads the reply for
phrases such as "saved to persistent memory". It never opens a second session, so it cannot show
that a planted value survives one. An agent that keeps memory across conversations (a store keyed
by user, a LangGraph `Store`, a vector store it writes) is only proven poisoned when a later,
clean session acts on what an earlier one planted.

After this change a vector prompt can carry `new_session: true`. `TacticExecutor` (the multi-turn
path every non-`single`, non-`pair` vector already takes) calls `adapter.reset_state()` before
that prompt, so the conversation starts over while the agent's own memory stays. The result's
evidence holds one record per session: its index, the prompts sent, the replies, and the tool
calls. A session-2 prompt carries success indicators as any multi-turn turn does; the verdict on
it is a signal, the per-session tool calls are the proof a caller checks.

Most adapters clear everything on `reset_state()`, or ziran cannot tell. A new adapter attribute
`memory_persists_across_reset` (default `False`) says whether the target keeps memory across a
reset; a remote target sets it in its YAML (`memory_persists_across_reset: true`). A vector with a
`new_session` prompt against an adapter without it sends nothing and returns a result with
`evidence.skipped = "no memory across sessions"` and `evidence.outcome = "unmeasured"`, so the
scan lists it under `unmeasured_vectors` (spec 082), never as passed.

One new vector, `mp_cross_session_plant_trigger`, plants an instruction naming an outside address
in session 1 and asks a routine task in session 2. It maps to ATLAS AML.T0080 and AML.T0080.000
(AI Agent Context Poisoning: Memory) and OWASP Agentic ASI06.

No file under `ziran/application/detectors/` changes; `scanner.py` and `attack_executor.py` do not
change.

## Acceptance scenarios

1. **Given** an adapter whose `memory_persists_across_reset` is true, **When** the plant-trigger
   vector runs, **Then** `reset_state()` is called once, between the plant and the trigger, and
   `evidence.sessions` holds two records: session 1 with the plant prompt and reply, session 2
   with its prompt, reply and tool calls.
2. **Given** an adapter without persistent memory (the default), **When** the vector runs,
   **Then** nothing is sent, `evidence.skipped` is "no memory across sessions" and
   `evidence.outcome` is "unmeasured", so the vector is counted unmeasured, not passed.
3. **Given** the same run, **When** the detector pipeline evaluates it, **Then** no file under
   `ziran/application/detectors/` changed (checked with `git diff --stat origin/develop`).

## Requirements

- **FR-001** `AttackPrompt.new_session: bool = False`.
- **FR-002** `AttackVector` rejects a `new_session` prompt unless the tactic runs through
  `TacticExecutor` (not `single`, not `pair`): the single path would ignore the flag.
- **FR-003** `BaseAgentAdapter.memory_persists_across_reset: bool = False`; the HTTP adapter takes
  it from `TargetConfig.memory_persists_across_reset`. The `reset_state` docstring says memory the
  target keeps on its side may survive.
- **FR-004** `TacticExecutor` resets before each `new_session` prompt and records
  `evidence.sessions` on both the success and the failure result of such a vector; vectors without
  the flag keep their evidence unchanged.
- **FR-005** Skip with reason as in scenario 2.
- **FR-007** While the adapter declares memory across reset, every `TacticExecutor` run on it
  holds a per-adapter gate: multi-turn runs share it, a two-session run holds it alone (review
  round 1: a reset beside another multi-turn run gave a false finding and wiped that run's
  build-up).
- **FR-008** After each session-2 turn the adapter's history must hold only that session's own
  prompts and replies; otherwise the result is unmeasured with `unmeasured_reason`
  "session 2 shared". A plant with no reply stops the run before session 2, unmeasured with
  "session 1 got no reply".
- **FR-009** Each session record lists its turns (`turn`, `prompt`, `reply`, `tool_calls`), so a
  failed turn cannot misalign prompts and replies.
- **FR-006** The new vector, mapped as above; the ATLAS agent-technique fitness test lists it.

## Edge cases

- A turn that fails (timeout, connection error) still counts toward its session; the session
  record holds what was sent.
- A `new_session` flag on the first prompt resets before it; harmless.
- The run plants a value in the target's memory and ziran cannot remove it: the vector
  description names the planted instruction so the operator can delete it.

## Assumptions

- "Counted as skipped" uses the existing unmeasured list (`outcome: unmeasured`,
  `unmeasured_vectors`), plus the `skipped` reason the many-shot skip already uses. Overturned if
  the owner wants a separate skipped count in the result metadata.
- Persistence is declared, not probed: ziran cannot see a target's memory, and a probe would
  itself plant a value. Overturned by a target that exposes its memory for inspection.
- The gate is shared/exclusive rather than one mutex for every multi-turn run: a mutex would
  serialise all multi-turn vectors on a declared target and push queued ones past the 60 s
  per-attack timeout. Overturned if serialising all of them is preferred.
- Single-prompt vectors do not take the gate (their path is `attack_executor.py`, which has no
  room); the history check catches their turns landing in session 2.
- `compute_resilience` still counts the skip as resisted, as it does every spec 082 unmeasured
  outcome; left for a follow-up that drops unmeasured rows from its total.
- The vector uses the `context_buildup` tactic rather than a new tactic name, so the tactics
  histogram and every tactic consumer stay as they are.
