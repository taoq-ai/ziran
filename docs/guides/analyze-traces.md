# Analyzing production traces

`ziran analyze-traces` ingests production traces (OTel JSONL or Langfuse), reconstructs per-session tool-call sequences, and flags sequences that match dangerous tool chains. See [OTel tracing](otel-tracing.md) for how to export traces.

```bash
ziran analyze-traces --source otel --input traces.jsonl --out ./reports
```

## Alerting

By default the command writes a report file. With `--alert`, dangerous-chain matches are also delivered to the notification sinks declared in a config file, so the operator who can fix the issue hears about it.

```bash
ziran analyze-traces --source otel --input traces.jsonl \
  --alert --config alerts.yaml
```

`alerts.yaml` carries an `alerts:` block (the same schema used by `watch-registry`). Secrets are resolved from the environment via the `!env` tag — never commit them:

```yaml
alerts:
  - kind: github_issue
    repo: myorg/ai-agent-infra
    token: !env GH_TOKEN
    labels: [trace-finding, security]
    severity_floor: high
  - kind: slack
    webhook_url: !env SLACK_WEBHOOK_URL
    severity_floor: medium
```

Each filed GitHub issue includes the observed tool sequence, the session ID, the trace source, the (inherited) severity, and a suggested remediation when available.

### Per-session vs. digest

- Default: one issue per `(chain, session)` execution.
- `--digest`: aggregate all matches from the run into a single digest issue.

### Deduplication

Issues are deduplicated by a stateless fingerprint embedded in the issue body (`(tool-chain, session)` for per-session, the chain set for a digest). Re-running on the same traces opens **no** new issues. The digest fingerprint excludes the run date, so an unchanged set of chains reuses the same digest issue across days.

### Correlating pre-deploy findings

Pass `--predeploy-result scan.json` (a prior `CampaignResult`) to correlate production matches against pre-deploy findings by tool sequence. Matched findings inherit the pre-deploy severity and remediation, and the issue links back to the pre-deploy finding.

### Previewing and exit codes

- `--dry-run-alerts` prints what each sink would send and performs zero network I/O.
- Exit codes: `0` success · `2` partial delivery failure (detection ran, ≥1 sink failed) · `1` fatal/usage error.
