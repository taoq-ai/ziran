# LLM-as-a-Judge Detection

Enhance ZIRAN's detection pipeline with an AI-powered judge that evaluates
ambiguous attack responses using a secondary LLM.

## Architecture

```
Attack Prompt ──► Target Agent ──► Response
                                      │
                    ┌─────────────────┤
                    ▼                 ▼
              Deterministic       LLM Judge
              Detectors           (GPT-4o / Claude / Bedrock)
              (refusal,               │
               indicator,             ▼
               side-effect)     AI Verdict
                    │                 │
                    └────────┬────────┘
                             ▼
                      Final Verdict
```

## What it demonstrates

- Enabling the **LLM-as-a-judge** detector via `create_llm_client()`
- Passing the LLM client through `AgentScanner` config
- Using different LLM providers (OpenAI, Anthropic, Ollama) as the judge
- How the LLM judge complements deterministic detectors for ambiguous cases
- Comparing scan results **with** and **without** the LLM judge

## Prerequisites

- Python 3.11+
- `uv sync --extra langchain` (from `examples/`)
- `pip install litellm` or `uv pip install litellm`
- `OPENAI_API_KEY` set in environment or `../.env`

### Optional: use a different judge provider

```bash
# Anthropic
export ANTHROPIC_API_KEY=sk-ant-...

# Local Ollama (no API key needed)
ollama pull llama3.2
```

## Run

```bash
./run.sh
# or
uv run python main.py
```

### Use a specific judge provider

```bash
# Use Claude as the judge
uv run python main.py --judge-provider anthropic --judge-model claude-sonnet-4-20250514

# Use local Ollama
uv run python main.py --judge-provider ollama --judge-model llama3.2

# Use AWS Bedrock
uv run python main.py --judge-provider bedrock --judge-model anthropic.claude-3-haiku-20240307-v1:0
```

## Files

| File | Purpose |
|------|---------|
| [main.py](main.py) | Builds a vulnerable agent, scans with and without LLM judge |
| [run.sh](run.sh) | One-command launcher |

## Expected results

The LLM judge typically catches 1–3 additional vulnerabilities that
the deterministic detectors miss — especially subtle prompt leakage
and partial compliance responses where the agent "sort of" refuses
but still leaks information.
