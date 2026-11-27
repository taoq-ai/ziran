# Tasks: fail-safe goals and fault modes in the hostile MCP server

**Spec**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md)

## Phase 1: goals

- [x] T001 Write failing tests for the three goals, their validation and the scenarios
  (`tests/unit/test_failsafe_goals.py`); run red.
- [x] T002 Add the goal models and `GoalCall` roles (`ziran/domain/entities/goal.py`).
- [x] T003 Judge the new kinds (`ziran/application/goals/judge.py`).
- [x] T004 Pass the discovered tool names for a `hallucinated_tool` vector
  (`ziran/application/agent_scanner/trials.py`, `attack_executor.py`).

## Phase 2: fault modes

- [x] T005 Write failing tests for each fault and the CLI options
  (`tests/integration/test_mcp_hostile_faults.py`); run red.
- [x] T006 Add the fault tools to `build_server` and the CLI options.

## Phase 3: scenarios and docs

- [x] T007 Write `examples/31-failure-modes/vectors/failure_modes.yaml` and its README.
- [x] T008 Acceptance 1 with the server's real error text; acceptance 2 through `AgentScanner`.
- [x] T009 Document the goals and the fault modes.
- [x] T010 Run the touched tests on 3.11, 3.12 and 3.13, ruff, ruff format and mypy strict.
