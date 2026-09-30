# Claude Code Agent Audit

Audit a Claude Code subagent definition for dangerous tool chains, without running the agent or calling an LLM.

`agents/researcher.md` declares `tools: Read, WebFetch`. Neither tool is dangerous alone; together they are a data exfiltration path (`read_file -> http_request`).

## Prerequisites

- Python 3.11+
- `pip install ziran`

No API keys required.

## Run

```bash
ziran audit agents/
```

Add `--format json` for machine-readable output, or `--sarif audit.sarif` for GitHub code scanning.

## Expected output

Two findings: `SA003` (high, `WebFetch` is a dangerous tool) and `CC001` (critical, `data_exfiltration via Read -> WebFetch`). The command exits non-zero.
