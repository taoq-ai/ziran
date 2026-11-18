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

## Build slice 1 (follow-up item; not started)

Test-first: each implementation task follows a test task run red first. No network, no key.

Phase 1, model and stage:

1. B001 Failing tests: `PairConfig` defaults and bounds (`max_iterations` 0 and 101 rejected,
   `timeout_seconds` 0 rejected); a vector YAML with `tactic: pair` and a `pair:` block loads; the
   `attacker` stage is accepted by `UsageLedger.record` and sorts after `strategy`.
2. B002 Add `PairConfig`, `AttackVector.pair`, `TacticType.PAIR` and the `attacker` stage.

Phase 2, the executor (`tests/unit/test_pair_executor.py`, copying the spike's toy target and
scripted attacker):

3. B003 Failing tests, one per spec scenario: success at a known iteration with `prompt_used` and
   `pair` evidence; no attacker gives an error and no target call; `max_iterations` returns the
   best attempt; a token cap stops with `budget`; a short timeout stops with `timeout` and a best
   attempt; attacker tokens land under `attacker`; two runs with one seed give equal
   trajectories; a non-JSON attacker reply counts `attacker_parse_errors`; a `PendingResponse`
   stops with `pending`; no two attacker requests in one stream are equal.
4. B004 Implement `ziran/application/attacks/pair.py` per plan section 2, with the cost warning in
   its docstring.

Phase 3, wiring:

5. B005 Failing tests: `AttackExecutor` sends `tactic: pair` to `PairExecutor` and other tactics
   as before; `AgentScanner` passes a tracked `attacker_llm_client`; `PhaseExecutor` gives a PAIR
   vector `max(attack_timeout, pair.timeout_seconds)`.
6. B006 Wire `attack_executor.py`, `scanner.py` and `phase_executor.py`.

Phase 4, docs and gates:

7. B007 Add the cost warning and a `tactic: pair` YAML example to `docs/concepts/attack-vectors.md`.
8. B008 Run the touched test files, `uv run ruff check .`, `uv run ruff format --check .` and
   `uv run mypy ziran/`; take the full suite and coverage from CI.
