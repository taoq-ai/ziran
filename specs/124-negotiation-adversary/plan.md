# Implementation Plan: adversarial counterpart scenarios for negotiating agents

**Branch**: `feat/124-negotiation-adversary` | **Spec**: [spec.md](spec.md)

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13). Pydantic v2 (goal models), stdlib `re` and
`itertools`; no new dependency. Reads `call_name` and `call_args` from the provenance module,
unchanged.

## Approach

1. `ziran/domain/entities/goal.py`: `LimitBreachGoal` (with `breached(value)`), `SecretLeakGoal`
   (with `found_in(text)`, the whole-value regex), `amount` and `threshold` on
   `ApprovalBypassGoal`, both new kinds in the `SideEffectGoal` union, `Replies = dict[int, str]`.
   `GoalCall` gains roles `commitment` and `reply`; `call` and `tool` become optional for a reply.
2. `ziran/domain/entities/attack.py`: `AttackVector._check_secret` rejects a secret the vector
   sends itself.
3. `ziran/application/goals/judge.py`: `goal_status(goal, turns, replies=None)` with a branch per
   new kind; `_number(call, path)` reads a value from the arguments, or `output` when there are
   none. `judge_goal` passes `replies` through.
4. Recording: `AttackExecutor.execute` makes a `replies` dict beside `turns` and passes both to
   `_run`; the single path, `TacticExecutor`, `PairExecutor` and `CarrierExecutor` record
   `response.content` where they record `response.tool_calls`. `attack_executor.py` stays under
   the 400-line cap.
5. `examples/29-negotiation-agent/`: `vectors/negotiation.yaml` (nine scenarios) and a README
   that says to set the limits first. A row in `examples/README.md`.
6. `docs/concepts/attack-vectors.md`: a "Negotiation goals" section and the `goal` row.

## Constitution check

- Hexagonal: the models are domain entities with no outer import; the judge stays in application.
- Type safety: Pydantic models, mypy strict, no `Any` in new signatures beyond the call dicts.
- New vectors are YAML, not code (principle V).
- Tests: unit tests for models and judge, the three acceptance scenarios (one over the A2A
  adapter), every execution path, and a scan through `AgentScanner`.
- Size: `scanner.py` unchanged; `attack_executor.py` at 393 of 400 lines.
- Unchanged: detectors, hybrid judge, role typing, tool aliases, `chain_patterns.yaml`.

## Test plan

- `tests/unit/test_negotiation_goals.py`: model validation; whole-value secret matrix; limit
  floor, ceiling, nested and JSON-string paths, unreadable values; threshold sums, approval
  order, single order over and under; secret evidence and unmeasured; acceptance 1 to 3 from the
  example YAML (acceptance 2 over `HttpAgentAdapter` with A2A on a mock transport); an A2A
  artifact commitment; replies on the single, PAIR and carrier paths; error replies; a campaign
  through `AgentScanner` reporting each scenario's `goal_met`.
- Touched-path tests: `test_side_effect_goals.py`, `test_tactics.py`, `test_pair_executor.py`,
  `test_phase_executor_pair.py`, `test_pair_wiring.py`, `test_carrier_executor.py`,
  `test_carriers.py`, `test_evidence_rule.py`, `test_expanded_tactics.py`,
  `test_attack_library.py`, `test_owasp_agentic_mapping.py`, `application/test_trials.py`,
  `application/test_scanner_size.py`, `integration/test_memory_two_session_scan.py`,
  `integration/test_a2a_identity_scan.py`.
