# Implementation Plan: OpenAI Agents SDK adapter

**Spec**: [spec.md](spec.md)

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13). New optional dependency `openai-agents>=0.20,<1`
(extra `openai-agents`, in `all`); the universal lock resolves 0.20.0 because `crewai>=1.14`
caps pydantic below what 0.21+ needs, and moves `openai` 2.43.0 to 2.54.0. The package ships
`py.typed`, so no mypy override.

## Constitution check

- Hexagonal: the adapter lives in `infrastructure/adapters`, implements `BaseAgentAdapter`;
  the application layer loads it lazily in `factories.py`, as for the other frameworks.
- Type safety: annotated, mypy strict; domain data in existing Pydantic models
  (`AgentCapability`, `MultiAgentTopology`).
- Tests: offline unit tests with a scripted `agents.models.interface.Model`; no network.
- Simplicity: one module, the LangGraph adapter's shape; no new abstraction.

## Design

`openai_agents_adapter.py`:

- Import guard: `from agents import Agent, Handoff, Runner` inside `try`, `ImportError` naming
  `uv sync --extra openai-agents`.
- `_walk(agent)`: breadth-first over `agent.handoffs` keyed by agent name; yields
  `(agent, [(target_name, target_agent_or_None, handoff_or_None)])`.
- `invoke`: `Runner.run(self.agent, [*self._input, {"role": "user", "content": message}])`;
  outputs map `call_id -> str(ToolCallOutputItem.output)`; inputs `json.loads(arguments)`,
  falling back to the raw string.
- `discover_capabilities`: FunctionTool fields `name`, `description`, `params_json_schema`;
  other tool types by `name` only.
- `discover_structure`: nodes `openai_agents:<name>`, role `agent`; edges per handoff.

Wiring: two `click.Choice` lists in `ziran/interfaces/cli/main.py`, one branch in
`load_agent_adapter`, the extra in `pyproject.toml`, `uv lock`.

## Files

- `ziran/infrastructure/adapters/openai_agents_adapter.py` (new)
- `tests/unit/test_openai_agents_adapter.py` (new)
- `ziran/application/factories.py`, `ziran/interfaces/cli/main.py`, `pyproject.toml`, `uv.lock`
- `examples/26-openai-agents-scan/{agent.py,README.md}`, `examples/README.md`
- `docs/guides/adapters.md`
