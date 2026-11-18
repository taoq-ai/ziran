# Tasks: AutoGen AgentChat adapter

Test-first: each implementation task follows a failing test run. Offline, no API key.

## Phase 1 - Dependency

- [ ] T001 Add the `autogen` extra (and to `all`) and the mypy overrides in `pyproject.toml`;
      `uv lock`.

## Phase 2 - Adapter (FR-001 to FR-005, FR-009)

- [ ] T002 Failing tests `tests/unit/test_autogen_adapter.py`: construction, capabilities of
      an agent and of a nested team (acceptance 1), round-robin, selector, Swarm and user-proxy
      structure and knowledge-graph import (acceptance 2), invoke with a stub refusal plus
      `send_email` and the side-effect detector (acceptance 3), concurrent turns, deferred
      reset, the private-attribute guard.
- [ ] T003 Implement `ziran/infrastructure/adapters/autogen_adapter.py`; T002 passes.

## Phase 3 - Wiring (FR-006)

- [ ] T004 Failing tests: `load_agent_adapter("autogen", example)` finds `team`; a missing
      package gives the `uv sync --extra autogen` hint; the CLI accepts `--framework autogen`
      on `scan` and `discover`.
- [ ] T005 Implement the `factories.py` branch and the two `main.py` Choice entries.

## Phase 4 - Example and docs (FR-008)

- [ ] T006 `examples/27-autogen-agent/` (agent file, README), `examples/README.md` row,
      `docs/guides/adapters.md` section.

## Phase 5 - Gates

- [ ] T007 `uv lock --check`, ruff check, ruff format --check, mypy ziran/ (dev-only env),
      pytest --cov=ziran.
