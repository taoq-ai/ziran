# Quickstart: Runtime Loop Alerting and Automation

## 1. Alert on MCP registry drift (US1 / #272)

```yaml
# registry.yaml
servers:
  - name: prod-mcp-server
    url: https://mcp.prod.example.com
alerts:
  - kind: slack
    webhook_url: !env SLACK_WEBHOOK_URL
    severity_floor: medium
  - kind: github_issue
    repo: myorg/ai-agent-infra
    token: !env GH_TOKEN
    labels: [mcp-drift, security]
    severity_floor: high
```

```bash
export SLACK_WEBHOOK_URL=...    # never committed
export GH_TOKEN=...
ziran watch-registry --config registry.yaml             # alerts fire on drift
ziran watch-registry --config registry.yaml --dry-run-alerts   # preview, no sends
```

Re-running produces **no duplicate** GitHub issues (stateless fingerprint marker).

## 2. File issues from dangerous production traces (US2 / #274)

```bash
ziran analyze-traces traces.jsonl --config analyze.yaml --alert            # one issue per (chain, session)
ziran analyze-traces traces.jsonl --config analyze.yaml --alert --digest   # one aggregated issue per run
```

Each issue includes the observed tool sequence, a link to the matching pre-deploy finding (and existing issue if any), session ID, trace source link, inherited severity, and remediation when a policy bundle covers the chain.

## 3. Keep exported policies fresh (US3 / #273)

```yaml
# .github/workflows/policy-refresh.yml  (copied from examples/07-cicd-quality-gate/)
on:
  schedule: [{ cron: "0 6 * * 1" }]   # weekly
  workflow_dispatch:
jobs:
  refresh:
    runs-on: ubuntu-latest
    permissions: { contents: write, pull-requests: write }
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/export-policy
        with:
          target: examples/01-langchain-agent/agent.yaml
          out-dir: policies/
          target-formats: rego,cedar
          reviewer-team: secops
```

Stale bundle → a single `ziran/policy-refresh` PR is opened/updated. Current bundle → no PR. Set `fail-on-diff: "true"` to hard-block instead.

## Exit codes (scheduling)

| Code | Meaning |
|---|---|
| 0 | All eligible findings delivered (or nothing eligible). |
| 2 | Partial delivery failure — detection ran, ≥1 sink failed. |
| 1 | Fatal/usage error (bad config, unset `!env` var) **or** the pre-existing `watch-registry` severity gate (critical/high drift present). |

> Note: exit `1` is overloaded on `watch-registry` — it signals both a fatal error and the existing "critical/high findings present" severity gate. Schedulers that need to distinguish a crash from a severity gate should parse the run output, not rely on the code alone. Precedence: fatal(1) > delivery-failure(2) > severity-gate(1) > 0.

## Verify locally

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy ziran/
uv run pytest -m "unit or integration" --cov=ziran
```

Integration tests use respx — no real Slack/GitHub calls.
