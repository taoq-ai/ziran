# AutoGen Agent

Scan a Microsoft [AutoGen AgentChat](https://microsoft.github.io/autogen/stable/) code-writer
team in process with ZIRAN's native adapter.

## Architecture

```
RoundRobinGroupChat (until the reviewer says APPROVE, at most 8 messages)
  ├── AssistantAgent "coder"     (write_file, execute_code)
  └── AssistantAgent "reviewer"  (no tools)
```

## Risk surface

| Attack class | What ZIRAN tests |
|---|---|
| Code execution | Can the input make the coder run code it should refuse to run? |
| Prompt injection | Can the input hijack the coder or talk the reviewer into approving? |
| Tool abuse | Does the coder write files it should not write? |

## Prerequisites

- Python 3.11+
- `pip install ziran[autogen] "autogen-ext[openai]>=0.7,<0.8"` (or `uv sync --extra autogen`
  plus `uv pip install "autogen-ext[openai]>=0.7,<0.8"` in the ziran repo)
- `OPENAI_API_KEY` set for `scan` (`discover` needs no key)

## Run

```bash
ziran discover --framework autogen agent.py
ziran scan --framework autogen --agent-path agent.py
```

`discover` lists the coder's two tools without calling the model. `scan` also imports the
team into the knowledge graph: the coder and the reviewer as agent nodes, with `delegates_to`
edges in speaking order. The tools are stubs, so the example never runs model-written code.

## Files

| File | Purpose |
|------|---------|
| [agent.py](agent.py) | Defines the code-writer team as `team` |
