Verdict: PASS
Gate: quality
Item: G2-OPENAI-AGENTS
PR: taoq-ai/ziran#502
Head: e30ae7044c8ab33ae931fb3d8352a38d6b360e98
Confidence: medium
Breaking: no

## Findings
none

## Probes
- closed: pyproject.toml mypy import-not-found (agents, agents.items) at e30ae70. A bare CI-style environment (`uv sync --frozen --group dev`, no extras) now gives `Success: no issues found in 224 source files`; CI `typecheck` is green.
- closed: untested `_agent_ref` branch at e30ae70. In a fresh `git archive e30ae70` copy, mutant `target if isinstance(target, Agent) else None` -> `None` is KILLED by `TestDiscoverStructure::test_handoff_object_target_tools_discovered`.
- Delta checks in a fresh archive copy (openai-agents 0.20.0, extras openai-agents/langchain/crewai): ruff check clean, ruff format --check clean (527 files), `uv lock --check` current, adapter tests 16 passed (14 before plus the 2 new), adapter module 97% (uncovered 33-34, 88 as before). The same 16 pass with openai-agents 0.25.0 (openai 3.55.0, pydantic 2.14.3). CI at this head: test 3.11/3.12/3.13, typecheck, lint, integration-test, dependency-audit all pass.
- invoke change (append instead of replace), mutants all KILLED: `+=` -> `=` (test_concurrent_turns_both_kept), drop user_item, drop new_items, and `[*self._input, user_item]` -> `self._input` (the last three by test_history_kept_until_reset and test_concurrent_turns_both_kept). `+=` runs with no await between the snapshot read and the append, so two concurrent turns each append a contiguous [user, items...] block and neither is lost; reset_state rebinds `_input = []` and is unaffected. The concurrency test does not depend on wall-clock time or a shared file.
- Equivalence of the new history to `RunResult.to_input_list()`, checked by a generated differential on a scripted handoff run (support -> billing with a tool call) on both 0.20.0 and 0.25.0: identical (0 differences) for the default handoff (nest_handoff_history False). With `handoff(..., nest_handoff_history=True)` they differ: to_input_list rewrites the first item into the SDK's "conversation so far" summary, while the adapter keeps the raw transcript (user, handoff call, output, later tool calls). The adapter's version is the full record and the length is the same, so I judge it acceptable for scanning. It departs from the plan's wording "keeps the conversation with RunResult.to_input_list()" and from SDK-side filtering of approval items and reasoning-id policy (0.25 `run_item_to_input_item`); neither is reachable from the adapter's default setup (no RunConfig, no needs_approval tools).
- The docs tracing sentence names `OPENAI_AGENTS_DISABLE_TRACING=1` and `agents.set_tracing_disabled(True)`; the test file already calls the latter. Docs only, no gate.
- Still unmeasured: full-suite coverage locally (CI test jobs passed with the coverage gate). Survivors from the first review (kwargs passthrough, last_agent metadata, observed-call bookkeeping, final_output None) remain untested; they are `blocks: no` and were reported at 24b1f19.
- Simplicity: none. The change replaces one SDK call with a short list expression and removes the lost-update window; nothing new is deletable.

## Residual risk
Adapter history now diverges from to_input_list under `nest_handoff_history=True` and, on SDK versions that filter approval or reasoning items, would carry them raw; neither is reachable with the adapter's defaults. The `_agent_ref` private-attribute dependency is now tested, so SDK drift fails a test instead of silently dropping tools.
