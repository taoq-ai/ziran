# Plan: two-session memory poisoning

**Spec**: `specs/113-memory-two-session/spec.md`

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13), Pydantic v2. No new dependencies.

## Design

- `ziran/domain/entities/attack.py`: `AttackPrompt.new_session` field; an `AttackVector` validator
  for FR-002.
- `ziran/domain/interfaces/adapter.py`: class attribute `memory_persists_across_reset = False` on
  `BaseAgentAdapter`; `reset_state` docstring.
- `ziran/domain/entities/target.py`: `TargetConfig.memory_persists_across_reset`.
- `ziran/infrastructure/adapters/http_adapter.py`: copy the config value onto the adapter in
  `__init__`.
- `ziran/application/attacks/tactics.py`: skip check at the top of `execute`; before a
  `new_session` prompt call `reset_state()` and open a new session record; append prompt, reply
  and tool calls to the current record; add `sessions` to the evidence of both results when the
  vector has a `new_session` prompt.
- `ziran/application/attacks/vectors/memory_poisoning.yaml`: `mp_cross_session_plant_trigger`.
- Docs: the vector and target-config references; regenerated benchmark coverage numbers.

Untouched by design: `scanner.py` (749/750), `attack_executor.py` (399/400), everything under
`ziran/application/detectors/`.

## Tests

- `tests/unit/test_tactics.py`: scenario 1 (reset order, two session records, tool calls in
  session 2), scenario 2 (skip, nothing sent, unmeasured), the validator (FR-002), vectors without
  the flag carry no `sessions` key.
- `tests/unit/test_http_adapter*.py` or `test_tactics.py`: the HTTP adapter reads the config flag.
- `tests/unit/test_atlas_agent_techniques.py`: the new vector in the MEMORY set.
