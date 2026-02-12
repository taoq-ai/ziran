# Static Analysis

Scan Python source files for hard-coded secrets, dangerous patterns, and prompt-injection risks — **without running any agent or LLM**.

## What it demonstrates

- Analysing a single file for security issues
- Analysing an entire directory recursively
- Custom `StaticAnalysisConfig` with organisation-specific patterns
- Merging default + custom config

## Prerequisites

- Python 3.11+
- `pip install ziran` (or `uv sync` from `examples/`)

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
| [main.py](main.py) | Example script — runs static analysis demos |
| [sample_agent.py](sample_agent.py) | Intentionally insecure code used as scan input |
| [run.sh](run.sh) | One-command launcher |

## Expected output

Rich-formatted tables showing findings with severity, line numbers, and context for each detected issue (hardcoded API keys, SQL injection, PII exposure, etc.).
