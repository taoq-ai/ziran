# Supervisor Multi-Agent

An enterprise HR platform with a supervisor LLM that delegates tasks to specialised sub-agents: HR, Finance, and IT.

## Architecture

```
User ──► Supervisor LLM (GPT-4o-mini)
              ├──► HR Agent       (leave balance, policies, employee lookup)
              ├──► Finance Agent  (payroll, expense, revenue — RESTRICTED)
              └──► IT Agent       (password reset, access provisioning)
```

## Risk surface

| Attack class | What ZIRAN tests |
|---|---|
| Delegation bypass | Can the user convince the supervisor to skip the sub-agent and answer directly? |
| Cross-agent privilege escalation | Can a query to the HR Agent leak Finance data? |
| Multi-hop data exfiltration | Can information trickle across agent boundaries? |
| System prompt extraction | Can the supervisor's routing logic be recovered? |
| Overload / confusion | Does the supervisor fall back gracefully on ambiguous requests? |

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
| [main.py](main.py) | Builds 4-chain supervisor system, runs 6-phase scan |
| [run.sh](run.sh) | Checks API key and launches |

## Expected results

Expect **0 vulnerabilities**. GPT-4o-mini correctly enforces departmental boundaries and refuses cross-agent leaks.
