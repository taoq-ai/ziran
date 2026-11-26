# Implementation Plan: `ziran scan --attacker-model`

**Branch**: `feat/127-scan-attacker-flag` | **Spec**: [spec.md](spec.md)

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13) + Click; reuses `create_llm_client`, `BaseLLMClient`,
`PairExecutor` (spec 081), the usage ledger (spec 047) and the warnings channel (spec 086). No new
dependencies. The `llm` extra stays optional.

## Constitution check

- Hexagonal: the CLI (interfaces) builds the infrastructure client; the application layer only
  sees a `BaseLLMClient` or `None`. Pass.
- Type safety: mypy strict on `ziran/`. Pass.
- Size: `scanner.py` stays at 750 lines (no change there); `phase_executor.py` 380 and `pair.py`
  336, both under 400.
- Paper freeze: detectors, hybrid judge, role typing, tool aliases and chain patterns untouched.

## Design

1. `ziran/application/attacks/pair.py`: `runnable(attacks, attacker, warnings)` drops PAIR
   vectors when `attacker is None` and appends one not-run line, deduplicated across phases.
2. `ziran/application/agent_scanner/phase_executor.py`: call it right after the A2A probe filter,
   with the attack executor's `attacker` (renamed from `_attacker` so the phase can read it).
3. `ziran/interfaces/cli/main.py`: the `--attacker-model` option, the client build with a
   `ClickException` on `ImportError`, a config table row, the attacker model in the `--max-cost`
   price check, and the result warnings printed after the summary table.
4. Docs: attack vectors concept page, CLI reference, runtime config, the negotiation example.

## Tests

`tests/unit/test_cli_attacker_model.py` runs the real scan through Click with the toy guard agent
and a scripted attacker put in place of `create_llm_client`: the PAIR loop with evidence, the
not-run listing, attacker tokens in the usage ledger, the price warning, and the missing-extra
error. `tests/unit/test_negotiation_goals.py` moves to the not-run contract.
