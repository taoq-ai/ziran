# Quickstart: Extract Shared Adapter & Strategy Factories

**Feature**: 002-extract-shared-factories
**Date**: 2026-03-20

## What This Changes

This refactor moves adapter and strategy creation logic from CLI-private functions into a shared application-layer module (`ziran/application/factories.py`). The CLI is updated to import from the new location.

## Usage After Refactor

### Creating a Remote Adapter (HTTP/Browser)

```python
from ziran.application.factories import load_remote_adapter

adapter = load_remote_adapter("targets/my_agent.yaml")
adapter = load_remote_adapter("targets/my_agent.yaml", protocol_override="browser")
```

### Creating a Framework Adapter (LangChain/CrewAI/Bedrock/AgentCore)

```python
from ziran.application.factories import load_agent_adapter

adapter = load_agent_adapter("langchain", "my_agent.py")
adapter = load_agent_adapter("bedrock", "agent-id-123")
adapter = load_agent_adapter("bedrock", "config.yaml")
```

### Creating a Campaign Strategy

```python
from ziran.application.factories import build_strategy

strategy = build_strategy("fixed", stop_on_critical=True)
strategy = build_strategy("adaptive", stop_on_critical=False)
strategy = build_strategy("llm-adaptive", stop_on_critical=True, llm_client=my_llm)
```

## Error Handling

Factory functions raise standard Python exceptions (not `click.ClickException`):
- `ValueError` — unsupported framework name, invalid config
- `ImportError` — optional dependency not installed (message includes install command)
- `FileNotFoundError` — target config or agent file not found

Interface layers (CLI, web) should catch and convert to their own error types.

## Files Changed

| File | Change |
|------|--------|
| `ziran/application/factories.py` | **NEW** — shared factory functions |
| `ziran/interfaces/cli/main.py` | **MODIFIED** — imports from factories, removes private functions |
| `tests/unit/application/test_factories.py` | **NEW** — unit tests for factories |
