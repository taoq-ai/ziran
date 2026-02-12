# Dynamic Vector Generator

Generate tailored attack vectors based on an agent's discovered capabilities.

## What it demonstrates

- Creating `AgentCapability` objects manually
- Generating targeted attack vectors from capabilities
- How tool combinations produce exfiltration-chain vectors
- Comparing simple vs dangerous tool sets

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
| [main.py](main.py) | Example script — generates dynamic vectors |
| [run.sh](run.sh) | One-command launcher |

## Expected output

Rich tables showing generated vectors for a simple agent (1 tool) vs a dangerous agent (shell + file + email + database), with exfiltration chain detection highlighted.
