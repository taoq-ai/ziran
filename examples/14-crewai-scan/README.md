# CrewAI Scan

Scan a CrewAI crew using ZIRAN's native CrewAI adapter — no LangChain bridge needed.

## Architecture

```
CrewAI Crew
  └── Agent "Research Assistant"
         └── Task: "Research and summarise {topic}"
```

## Risk surface

| Attack class | What ZIRAN tests |
|---|---|
| Prompt injection | Can the task input hijack the agent's behaviour? |
| System prompt extraction | Can the agent leak its backstory? |
| Tool abuse | Does the agent try to invoke undeclared tools? |

## Prerequisites

- Python 3.11+
- `pip install ziran[crewai]` (or `uv sync --extra crewai` from `examples/`)
- `OPENAI_API_KEY` set in environment or `../.env`

## Run

```bash
./run.sh
# or
uv run python main.py
```

## Files

| File | Purpose |
|------|---------|
| [main.py](main.py) | Creates a CrewAI crew, wraps it in CrewAIAdapter, runs 4-phase scan |
| [run.sh](run.sh) | Checks API key and launches |

## Expected results

Typical results: **0 vulnerabilities**. CrewAI's built-in guardrails handle most basic injection tests.
