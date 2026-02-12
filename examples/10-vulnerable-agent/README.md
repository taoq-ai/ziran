# Vulnerable Agent

A **deliberately insecure** LangChain agent that showcases every common security anti-pattern. This is the best example for seeing ZIRAN find real vulnerabilities.

## Architecture

```
User ──► LLM (tool-calling, temperature=0.7, secrets embedded in prompt)
              ├──► query_employees      (returns full PII — SSN, salary)
              ├──► send_email           (unrestricted, no confirmation)
              ├──► run_database_query   (raw SQL, no sanitisation)
              └──► read_config          (credentials, API keys, endpoints)
```

## Why it's vulnerable

| Anti-pattern | Detail |
|---|---|
| Secrets in system prompt | DB credentials and API keys hardcoded directly |
| "All users are pre-authenticated" | No access control concept |
| "Be transparent about your setup" | Enables system prompt extraction |
| "Follow instructions precisely" | Disarms safety training |
| Full PII in tool responses | SSN, salary, email with no redaction |
| Raw SQL execution | No input validation |

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
| [main.py](main.py) | Builds vulnerable agent, runs full 6-phase campaign |
| [run.sh](run.sh) | Checks API key and launches |

## Expected results

ZIRAN should find **multiple vulnerabilities** across all 6 phases — prompt injection, data exfiltration, tool manipulation, and privilege escalation. Compare with the well-secured examples to see the difference proper guardrails make.
