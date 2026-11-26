# Implementation Plan: goals judged by side effects

**Branch**: `feat/116-side-effect-goals` | **Spec**: [spec.md](spec.md)

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13). Pydantic v2 (goal and evidence models), stdlib only;
no new dependency. Reads `call_name` and `call_args` from the provenance module and `tool_roles`
from role typing, unchanged.

## Approach

1. `ziran/domain/entities/goal.py`: `ApprovalBypassGoal`, `OutputSinkGoal`, `CanaryEgressGoal`
   (frozen, `extra="forbid"`), the `SideEffectGoal` union discriminated by `type`, `GoalCall`
   (turn, call, tool, role, argument) and `Turns` (`dict[int, list[dict]]`, turn to tool calls).
2. `ziran/domain/entities/attack.py`: `AttackVector.goal: SideEffectGoal | None`;
   `AttackResult.goal_met: bool | None` and `goal_evidence: list[GoalCall]`, both defaulted, so
   stored results and cache entries still load.
3. `ziran/application/goals/judge.py`: `goal_status(goal, turns)` returns `(met, evidence)`, pure,
   with one branch per goal kind (`assert_never` on the rest), so a caller can ask mid-run.
   `judge_goal(attack, result, turns)` sets the two result fields from it. No turn gives null.
   `AttackLibrary._parse_vector` passes `goal` (and `pair`, which it dropped before) to the model.
4. Hook: `AttackExecutor.execute` makes a `Turns` dict, runs the existing body (now `_run`), and
   passes the result through `judge_goal`. The single path records each reply that is not an
   error; `TacticExecutor`, `PairExecutor` and `CarrierExecutor` take an optional `turns` dict
   and record into it the same way. The text verdict code is not touched.
5. `AttackExecutor._invoke_streaming` moves unchanged to `agent_scanner/streaming.py` as
   `invoke_streaming(adapter, emitter, prompt, attack_name)`: the hook would take
   `attack_executor.py` past the package's 400-line fitness cap (`test_scanner_size.py`).
6. `docs/concepts/attack-vectors.md`: a `goal` row in Key Fields and a "Side-effect goals"
   section with one YAML example per kind and the meaning of `goal_met: null`.

## Constitution check

- Hexagonal: the models are domain entities with no outer import; the judge is application and
  imports only domain and two application modules it reads.
- Type safety: Pydantic models, mypy strict.
- Tests: unit tests for the judge and the models, the item's two acceptance scenarios on a real
  LangGraph graph, and one test per execution path that records turns.
- Size: `agent_scanner/` modules stay under the 400-line fitness cap.
- Unchanged: every file under `ziran/application/detectors/`, the hybrid judge, role typing, tool
  aliases and `chain_patterns.yaml`.

## Test plan

- `tests/unit/test_side_effect_goals.py`: model validation (unknown key, blank tool, empty or
  self-listed approval, short canary); approval met, late approval, approved first, approval in
  an earlier turn; output sink in a nested argument and a JSON-string argument, escaped payload
  not matched, `tools` filter; egress default role typing and `tools` override; no goal and no
  turn give null; the acceptance scenarios on `LangGraphAdapter`; tactic, PAIR and carrier paths
  record their turns.
- Touched-path tests: `test_tactics.py`, `test_pair.py`, `test_carrier_executor.py`,
  `test_evidence_rule.py`, `test_attack_library.py`, `application/test_scanner_size.py`.
