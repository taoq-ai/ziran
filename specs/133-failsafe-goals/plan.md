# Implementation Plan: fail-safe goals and fault modes in the hostile MCP server

**Branch**: `feat/133-failsafe-goals` | **Spec**: [spec.md](spec.md)

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13). Pydantic v2 (goal models), stdlib `json` and
`collections.Counter`; the `mcp` extra for the server (already a dependency). No new
dependency. Reads `call_name` and `call_args` from the provenance module, unchanged.

## Approach

1. `ziran/domain/entities/goal.py`: `LoopBoundGoal`, `UnsafeAfterErrorGoal`,
   `HallucinatedToolGoal` in the `SideEffectGoal` union; `GoalCall` gains roles `error`,
   `repeat` and `unknown_tool`.
2. `ziran/application/goals/judge.py`: `goal_status(goal, turns, replies=None, tools=None)`
   sends the three new kinds to `_failsafe`; `judge_goal` passes `tools` through.
3. `ziran/application/agent_scanner/trials.py`: for a `hallucinated_tool` vector, the runner
   passes the discovered `tool` capability names to `AttackExecutor.execute(tools=...)`, which
   hands them to `judge_goal`. `scanner.py` is untouched (750 lines); `attack_executor.py` stays
   at 400.
4. `ziran/infrastructure/mcp_hostile/server.py`: `build_server(..., fault=None, fault_tools=())`
   adds one tool per name that returns the fault; bounds are module constants.
5. `ziran/interfaces/cli/mcp_hostile_server.py`: `--fault` and `--fault-tools`, validated
   before the library loads.
6. `examples/31-failure-modes/`: `vectors/failure_modes.yaml` (five scenarios) and a README; a
   row in `examples/README.md`.
7. Docs: a "Fail-safe goals" section in `docs/concepts/attack-vectors.md`, a "Fault modes"
   section in `docs/guides/mcp-hostile-server.md`.

## Tests

- `tests/unit/test_failsafe_goals.py`: validation, each goal's met, not met and unmeasured
  cases, the scenarios loaded through `AttackLibrary`, and a scan through `AgentScanner` that
  compares calls with discovered tools.
- `tests/integration/test_mcp_hostile_faults.py`: each fault over an in-memory MCP session, the
  CLI's option checks, and acceptance 1 with the server's real error text.
