# Custom Agent Adapter

Implement `BaseAgentAdapter` to integrate any agent framework with ZIRAN — not just LangChain or CrewAI.

## What it demonstrates

- Implementing all required `BaseAgentAdapter` methods
- Simulating tool calls and capability discovery
- Using `get_state()` / `reset_state()` lifecycle methods
- Identifying high-risk capabilities
- Testing the adapter independently before plugging it into a scan

## Prerequisites

- Python 3.11+
- `pip install ziran`

No API keys required.

## Run

```bash
./run.sh
# or
uv run python main.py
```

## Files

| File | Purpose |
|------|---------|
| [main.py](main.py) | Complete adapter implementation + demo |
| [run.sh](run.sh) | One-command launcher |

## Expected output

Rich tables showing capability discovery, agent invocation with tool calls, state inspection, reset verification, and high-risk capability identification.
