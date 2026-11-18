# Tasks: PAIR attacker-LLM refinement as a vector tactic

Base: `origin/develop` @ c5d75eb. This PR is the spike: it stops before implement. The spike's
tasks are checked below. The build tasks are listed for the follow-up item without checkboxes,
since none of them is done here.

## Spike (this PR)

- [x] S001 Read the seams: `BaseLLMClient`, `RecordReplayClient`, `AttackExecutor`,
      `TacticExecutor`, `DetectorPipeline._resolve`, `LLMJudgeDetector`, `UsageLedger`,
      `CampaignBudget`, `PhaseExecutor` timeouts.
- [x] S002 Write `spike/pair_spike.py`: toy guarded target, scripted seeded attacker, scripted
      quality judge, one bounded PAIR stream through the existing seams.
- [x] S003 Measure 50 seeds with the graded and the binary signal; record `spike/result.json`.
- [x] S004 Check fixed-seed determinism (same seed equal, other seed differs, two processes equal).
- [x] S005 Check the token cap stops the loop.
- [x] S006 Run the attacker through the spec-064 cassette and count rounds and target calls.
- [x] S007 Write research.md, spec.md (go or no-go, cost warning, first slice), plan.md and this
      file.

## Build slice 1 (PR 1 built under item PAIR-PR1)

Test-first: each implementation task follows a test task run red first. No network, no key. Two
PRs. PR 1 (item PAIR-PR1) is B001 to B004 plus the `PhaseExecutor` half of B005 and B006 (PAIR
queued last, the phase extension, the deadline and its backstop, the `deadline` keyword on
`AttackExecutor.execute`). PR 2 is the rest of B005 and B006, then B007 and B008. PR 1 adds no
`tactic` value and no dispatch, so a release cut between the two runs no PAIR vector.

PR 1, phase 1, model and stage:

- [x] B001 Failing tests: `PairConfig` defaults and bounds (`max_iterations` 0 and 101 rejected,
   `timeout_seconds` 0 rejected, an unknown `seed` key rejected); a vector YAML with a `pair:`
   block loads; the `attacker` stage is accepted by `UsageLedger.record` and sorts after
   `strategy`.
- [x] B002 Add `PairConfig`, `AttackVector.pair` and the `attacker` stage.

PR 1, phase 2, the executor (`tests/unit/test_pair_executor.py`, copying the spike's toy target
and scripted attacker):

- [x] B003 Failing tests, one per spec scenario: success at a known iteration with `prompt_used` and
   `pair` evidence; no attacker gives an error and no target call; `max_iterations` returns the
   best attempt; a token cap stops with `budget`; a deadline in the past of the loop stops with
   `timeout` and a best attempt; attacker tokens land in the injected ledger under `attacker` and
   target tokens are not written there; `token_usage` sums every target call; a deterministic
   attacker gives equal trajectories on two runs; a non-JSON attacker reply counts
   `attacker_parse_errors`; a reply with a `reason` stops with `pending`; a raising target and a
   sentinel reply each add to `prompt_errors`; reserved metadata keys are dropped; no two attacker
   requests in one stream are equal.
- [x] B004 Implement `ziran/application/attacks/pair.py` per plan section 2, with the cost warning in
   its docstring and no runtime import from `ziran.infrastructure` other than logging.

Phase 3, wiring (`tests/unit/test_phase_executor_pair.py`); `[x]` items are in PR 1:

5. B005 Failing tests, with `phase_executor.PAIR_GRACE_SECONDS` patched to 0.05 so the timers
   stay under a second:
   - [ ] (PR 2) `AttackExecutor` sends `tactic: pair` to `PairExecutor` and other tactics as before;
     `AgentScanner` passes `attacker_llm_client` unchanged and its budget.
   - [x] Deadline: a PAIR vector stops with `pair.stop == "timeout"` and a best attempt, and is
     recorded. Built with scaled timers (phase 0.1 s, PAIR 0.3 s, slot opening at 0.3 s): with the
     extension in place, `timeout_seconds=60` would make the phase 60.5 s and the test a minute.
   - [x] Queued static vectors: `max_concurrent=2`, two PAIR vectors listed first and six static
     vectors after them, each static target call sleeping 0.05 s, `phase_timeout=0.5`. All six
     static results are recorded; each static vector acquires its slot before either PAIR vector
     (recorded acquire order); both PAIR vectors are recorded.
   - [x] Extension: with k PAIR vectors the phase runs under the extended timer and logs
     `phase_timeout_extended`; with none, the timer is `phase_timeout`.
   - [x] The deadline is taken after the slot is acquired: with `phase_timeout=2`, a PAIR vector of
     `timeout_seconds=0.3` that waits 0.2 s for a slot stops with `timeout` about 0.3 s after it
     acquires the slot, not 0.3 s after it was queued.
   - [x] A PAIR vector that gets its slot with less than the grace left is recorded as an error with
     no target call.
   - [ ] (PR 2) With `scan_cache` on, a failed PAIR result writes no entry.
6. B006 [x] `phase_executor.py` (plan section 3) and the `deadline` keyword in PR 1. [ ] (PR 2)
   Wire `TacticType.PAIR`, the `tactic` description, `attack_executor.py`, `scanner.py` (with
   the `track()` double-count warning in the `attacker_llm_client` docstring), the dispatch in `attack_executor.py`
   and `scan_cache.is_cacheable` (plan section 5).

PR 2, phase 4, docs and gates:

7. B007 Add the cost warning and a `tactic: pair` YAML example to `docs/concepts/attack-vectors.md`.
8. B008 Run the touched test files under `timeout 120`, `uv run ruff check .`,
   `uv run ruff format --check .` and `uv run mypy ziran/`; take the full suite and coverage from
   CI.
