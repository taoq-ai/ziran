# Tasks: two-session memory poisoning

- [x] T001 Write the failing tests: `tests/unit/test_tactics.py` (`TestNewSession`),
  `tests/unit/test_http_adapter.py` (config flag), `tests/unit/test_atlas_agent_techniques.py`
  (MEMORY set); run red (10 failed, 112 passed).
- [x] T002 `AttackPrompt.new_session`, the `AttackVector` tactic check, library parsing.
- [x] T003 `BaseAgentAdapter.memory_persists_across_reset`, `TargetConfig` field, HTTP adapter,
  `reset_state` docstring.
- [x] T004 `TacticExecutor`: skip with reason, reset before a `new_session` prompt, per-session
  records in both results.
- [x] T005 Vector `mp_cross_session_plant_trigger` in `memory_poisoning.yaml`.
- [x] T006 Integration test through `AgentScanner` and `HttpAgentAdapter`
  (`tests/integration/test_memory_two_session_scan.py`): two session records with memory, an
  unmeasured vector and nothing sent without it.
- [x] T007 Docs and regenerated benchmark coverage numbers for the new vector.
- [x] T008 Touched tests, `test_scanner_size.py`, the vector fitness tests, `ruff check`,
  `ruff format --check`, `mypy ziran/`.
- [x] T009 Review round 1: per-adapter session gate, shared-history check, failed-plant stop,
  per-turn session records, a race regression test beside a multi-turn vector with a 429 retry
  (red on the old head: a false finding), and the ATLAS table, field table, target key and
  REST session docs.
- [x] T010 Review round 2: count-based history check with a single-prompt race test, the A2A
  late-reply context guard with a test, gate tests for both wait rules and a double cancel, and
  the remote-agents guide limited to what the check guarantees.
