Verdict: PASS
Gate: quality
Item: G2-AUTOGEN
PR: taoq-ai/ziran#507
Head: 715e08903270606f9c65a1cbade80b6b3ccb4937
Confidence: medium
Breaking: no

## Findings
- [low] ziran/infrastructure/adapters/autogen_adapter.py:249 blocks: no. A Swarm handoff to a non-participant such as `handoffs=["user"]` gives an edge to the non-existent node `autogen:user`, which the scanner import skips silently. Carried over from 6838a92; untested, note for the PR.
- [low] ziran/infrastructure/adapters/autogen_adapter.py:77 blocks: no. `getattr(..., [])` on `_workbench`, `_participants` and `_handoffs` returns no tools or edges when an attribute vanishes, so a private-API drift looks like a clean agent. The `<0.8` pin and TestPrivateApi bound it. Carried over.
- [low] ziran/infrastructure/adapters/autogen_adapter.py:165 blocks: no. `setdefault` to `__setitem__` still survives; first-wins versus last-wins on a duplicate tool name is untested. Carried over.
- [low] ziran/infrastructure/adapters/autogen_adapter.py:122 blocks: no. `reset_state()` during an in-flight `invoke` leaves one stale history entry. Narrow race. Carried over.

## Probes
- closed: reset flag not cleared after the deferred reset (was blocking) at 715e089. Mutant `self._reset_pending = False` to `pass`, in a fresh `git archive 715e089` copy, now fails `TestInvoke::test_turns_kept_after_reset`.
- closed: `output_task_messages=False` untested at 715e089. Removing it fails `test_task_not_returned_as_answer`.
- closed: ring guard at 715e089. `len(member_ids) > 1` to `> 0` fails `test_one_member_round_robin_has_no_self_edge`.
- closed: `team` before `agent` order at 715e089. Swapping the fallback fails `test_team_preferred_over_agent`.
- closed: untested `stop_reason` and `last_speaker` metadata at 715e089. Both are removed, with the one assertion on them; metadata is now `{"framework": FRAMEWORK}`.
- Diff since 6838a92, apart from the develop merge (13969d6): only the adapter metadata lines, new tests, a docs line on UserProxyAgent stdin and the dependency bump already merged from develop. The guard and invoke code is unchanged, so the earlier mutant results hold.
- Re-run on the new head, each in a fresh copy, with the adapter, test_cli_main and test_factories tests: base 156 passed. Killed: lock removed (test_concurrent_team_turns_both_kept), deferred reset not run (test_history_kept_until_reset), team reset branch (test_team_reset), `_workbench`, `_handoffs` and `_participants` renames (test_agent_tools, test_swarm_handoff_edge, test_nested_team_tools_once), usage None guard and tool output dropped (test_refusal_with_tool_call), plus the four closed above.
- CI at 715e089 (read once): lint, typecheck, test 3.11, 3.12 and 3.13, dependency-audit, and the others pass; integration-test was still pending when I read it. Gate for the merge is its green result.
- I did not re-run ruff, mypy or `uv lock --check` locally at the new head; CI lint and typecheck pass, and the source change is a metadata dict only.

Simplicity: none left to delete after the metadata removal; `observe_tool_call` and `get_state` are the base interface.

## Residual risk
Silent degrade if a private AgentChat attribute disappears inside 0.7.x, bounded by the pin and TestPrivateApi. integration-test was pending when I read CI.
