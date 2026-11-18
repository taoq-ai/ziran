# OpenAI Agents Scan

Scan an [OpenAI Agents SDK](https://openai.github.io/openai-agents-python/) agent in process
with ZIRAN's native adapter.

## Architecture

```
Agent "support"  (read_file, send_email)
  └── handoff -> Agent "billing"  (lookup_invoice)
```

## Risk surface

| Attack class | What ZIRAN tests |
|---|---|
| Data exfiltration | Can an attacker chain `read_file` into `send_email`? |
| Prompt injection | Can the input hijack the agent or its handoff? |
| Tool abuse | Does the agent send email it should refuse to send? |

## Prerequisites

- Python 3.11+
- `pip install ziran[openai-agents]` (or `uv sync --extra openai-agents` in the ziran repo)
- `OPENAI_API_KEY` set for `scan` (`discover` needs no key)

## Run

```bash
ziran discover --framework openai-agents agent.py
ziran scan --framework openai-agents --agent-path agent.py
```

`discover` lists the three tools of both agents without calling the model. `scan` also
imports the `support -> billing` handoff into the knowledge graph as a `delegates_to` edge.

## Files

| File | Purpose |
|------|---------|
| [agent.py](agent.py) | Defines the support agent as `agent`, with the billing handoff |
