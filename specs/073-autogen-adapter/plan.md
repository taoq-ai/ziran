# Implementation Plan: AutoGen AgentChat adapter

**Spec**: [spec.md](spec.md)

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13). New optional dependency
`autogen-agentchat>=0.7,<0.8` (extra `autogen`, in `all`); the lock resolves 0.7.5 and adds
only `autogen-core` 0.7.5. CI's typecheck job syncs the dev group without extras, so the two
packages go in the mypy `ignore_missing_imports` overrides.

## Constitution check

- Hexagonal: the adapter lives in `infrastructure/adapters` and implements `BaseAgentAdapter`;
  `factories.py` loads it lazily, as for the other frameworks.
- Type safety: annotated, mypy strict; domain data in existing Pydantic models.
- Tests: offline unit tests with a stub `ChatCompletionClient` defined in the test; no network,
  no `autogen-ext`.
- Simplicity: one module in the shape of the OpenAI Agents adapter (spec 072); no new
  abstraction. `_load_python_object` gains fallback names so the file runs once.

## Design

`autogen_adapter.py`:

- Import guard: `autogen_agentchat.base` (`ChatAgent`, `Team`), `agents.UserProxyAgent`,
  `messages` events, `teams` classes; `ImportError` names `uv sync --extra autogen`.
- `_members(team)`: `getattr(team, "_participants", [])`, with a ponytail shortcut comment.
- `_agents(target)`: depth-first over nested teams, yields the agents.
- `invoke`: lock; await a pending reset; `await target.run(task=message)`; pair
  `FunctionCall.id` with `FunctionExecutionResult.call_id`; `json.loads` the arguments, falling
  back to the raw string.
- `discover_capabilities`: `for wb in getattr(agent, "_workbench", [])`: `await wb.list_tools()`
  gives `ToolSchema` dicts.
- `discover_structure`: recursive `_team_graph(team)` returning nodes and edges per FR-005.

Wiring: two `click.Choice` lists in `ziran/interfaces/cli/main.py`, one branch in
`load_agent_adapter`, the extra in `pyproject.toml`, `uv lock`.

## Files

- `ziran/infrastructure/adapters/autogen_adapter.py` (new)
- `tests/unit/test_autogen_adapter.py` (new)
- `ziran/application/factories.py`, `ziran/interfaces/cli/main.py`, `pyproject.toml`, `uv.lock`
- `examples/27-autogen-agent/{agent.py,README.md}`, `examples/README.md`
- `docs/guides/adapters.md`
