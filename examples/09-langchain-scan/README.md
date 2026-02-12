# LangChain Agent Scan

Scan a minimal LangChain ReAct agent (GPT-4o-mini) with two tools — database lookup and email sender.

## Architecture

```
User ──► LLM (ReAct loop)
              ├──► lookup      (database search)
              └──► send_email  (email delivery)
```

## What it demonstrates

- Wrapping a LangChain `AgentExecutor` with `LangChainAdapter`
- Running a 3-phase scan (reconnaissance, trust building, capability mapping)
- Live Rich progress bar during scanning
- Generating HTML, Markdown, and JSON reports

## Prerequisites

- Python 3.11+
- `pip install ziran[langchain]` (or `uv sync --extra langchain` from `examples/`)
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
| [main.py](main.py) | Builds agent, wraps with adapter, runs scan |
| [run.sh](run.sh) | Checks API key and launches |

## Expected results

GPT-4o-mini is well-hardened — expect **0 vulnerabilities** in most runs. The agent refuses social-engineering prompts and does not leak its system prompt.
