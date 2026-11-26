# Tasks: goals judged by side effects

**Spec**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md)

- [x] T001 Grep `ziran/` for an approval check, a goal field and per-turn tool-call records; trace every `AttackResult` construction in the four execution paths
- [x] T002 Write `tests/unit/test_side_effect_goals.py` and run it red
- [x] T003 Add `ziran/domain/entities/goal.py` and the `goal`, `goal_met` and `goal_evidence` fields in `attack.py`
- [x] T004 Add `ziran/application/goals/judge.py` (`judge_goal`)
- [x] T005 Hook `AttackExecutor.execute` and record turns in the single, tactic, PAIR and carrier paths; move the streaming helper to `agent_scanner/streaming.py`
- [x] T006 Run the new tests green on the real LangGraph adapter, then the touched-path and `AttackResult` tests
- [x] T007 Document `goal` in `docs/concepts/attack-vectors.md`
- [x] T008 Run ruff check, ruff format --check and mypy strict
- [x] T009 Gate round 1: the YAML loader passes `goal` (and the dropped `pair` config); the tactic path skips error replies when recording; an error-reply test per path; `goal_status(goal, turns)` split out as a pure check with explicit dispatch per kind
