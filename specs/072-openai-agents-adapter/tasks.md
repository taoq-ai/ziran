# Tasks: OpenAI Agents SDK adapter

Test-first: each implementation task follows a failing test run. Offline, no API key.

## Phase 1 - Dependency

- [x] T001 Add the `openai-agents` extra (and to `all`) in `pyproject.toml`; `uv lock`.

## Phase 2 - Adapter (FR-001 to FR-004)

- [x] T002 Failing tests `tests/unit/test_openai_agents_adapter.py`: construction, capabilities
      across the handoff tree (acceptance 1), structure and knowledge-graph import
      (acceptance 2), invoke with a scripted refusal plus `send_email` and the side-effect
      detector (acceptance 3), history and reset.
- [x] T003 Implement `ziran/infrastructure/adapters/openai_agents_adapter.py`; T002 passes.

## Phase 3 - Wiring (FR-005)

- [x] T004 Failing tests: `load_agent_adapter("openai-agents", example)` finds `agent`; a
      missing package gives the `uv sync --extra openai-agents` hint; the CLI accepts
      `--framework openai-agents` on `discover`.
- [x] T005 Implement the `factories.py` branch and the two `main.py` Choice entries.

## Phase 4 - Example and docs (FR-007)

- [x] T006 `examples/26-openai-agents-scan/` (agent file, README), `examples/README.md` row,
      `docs/guides/adapters.md` section.

## Phase 5 - Gates

- [x] T007 `uv lock --check`, ruff check, ruff format --check, mypy ziran/, pytest --cov=ziran.
- [x] T008 Run the adapter tests against openai-agents 0.25 in a scratch environment.
