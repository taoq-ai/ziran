# 136 executor split

Status: Active

Promise: move `_expand_many_shot` and the prompt-attempt build out of
`ziran/application/agent_scanner/attack_executor.py` into
`ziran/application/agent_scanner/prompt_attempts.py`, with no behaviour change.
`attack_executor.py` falls from 400 lines to under 340; `AttackExecutor` and the
re-exported `_ERROR_SENTINELS` and `_is_error_response` keep their import path.

Acceptance: the executor, many-shot, trials, campaign, PAIR, fail-safe and
scanner-size tests pass unchanged; `scanner.py` and the paper freeze are untouched.

Assumptions: no test reads `_expand_many_shot`, `_shot_renderer`, `_n_shots_override`
or `_context_window` (grep of `tests/` and `ziran/`), so the method becomes a function.
The executor still owns the lazy `ShotRenderer`. Overturned if a test patches the method.
