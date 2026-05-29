# Contract: CLI flags, config, and the policy-refresh Action

## CLI changes

### `ziran watch-registry`
- New: `--dry-run-alerts` (flag) — wrap all sinks, print payloads, no network I/O.
- Sinks are built from the `alerts:` block in the registry YAML (no new CLI flag needed for config path).
- Exit codes: `0` ok · `2` partial delivery failure · `1` fatal/usage. Existing severity-gate `SystemExit(1)` behavior preserved; precedence fatal(1) > delivery-failure(2) > severity-gate > 0.

### `ziran analyze-traces`
- New: `--alert` (flag) — emit dangerous-chain matches through configured sinks.
- New: `--digest` (flag) — aggregate the run's matches into a single digest issue (default off = per-`(chain, session)`).
- Config: `alerts:` block (same schema) supplied via the existing analyze config path.
- Same exit-code contract as above.

## Config schema (`alerts:` block)

```yaml
# registry.yaml (watch-registry)  /  analyze config (analyze-traces)
alerts:
  - kind: slack
    webhook_url: !env SLACK_WEBHOOK_URL
    severity_floor: medium
  - kind: github_issue
    repo: myorg/ai-agent-infra
    token: !env GH_TOKEN          # falls back to GITHUB_TOKEN if omitted
    labels: [mcp-drift, security]
    assignees: [secops-oncall]
    severity_floor: high
```

- `!env VAR` resolves at load via the custom loader; unset var → clear error before any send.
- `severity_floor` default `low`. Unknown `kind` → validation error listing allowed kinds.

## Composite Action: `.github/actions/export-policy/action.yml`

```yaml
name: ziran-policy-refresh
description: Re-scan a target, regenerate guardrail policies, open/update a refresh PR.
inputs:
  target:        { description: Path/URL of the agent target config, required: true }
  out-dir:       { description: Committed policy bundle dir, default: policies/ }
  target-formats:{ description: Comma list of rego,cedar,colang,invariant, default: "rego,cedar,colang,invariant" }
  fail-on-diff:  { description: Fail run on diff instead of opening a PR, default: "false" }
  reviewer-team: { description: Team slug to request review from, default: "" }
runs:
  using: composite
  # steps: install ziran -> ziran scan -> ziran export-policy --formats <...>
  #        -> diff vs out-dir -> if diff: (fail-on-diff ? exit 1 : commit to branch
  #        ziran/policy-refresh + gh pr create/edit, label policy-refresh, request reviewer)
```

**Behavior contract**:
- No diff → no PR, exit 0 (FR-020).
- Diff + `fail-on-diff=false` → commit to fixed branch `ziran/policy-refresh`, open PR if none exists for that branch else update it; label `policy-refresh`; request `reviewer-team` (FR-019).
- Diff + `fail-on-diff=true` → exit 1, no PR (FR-021).
- `target-formats` scopes regeneration + diff (FR-022).
- Fixed head branch guarantees a single PR under both squash and merge-commit base strategies (FR-024).
- Token: `${{ secrets.GITHUB_TOKEN }}` (or a passed PAT for cross-repo).

**Self-test** (`.github/workflows/policy-refresh-selftest.yml`): runs the action against the bundled example agent, asserts a PR is opened when the committed bundle is stale and none when current (US3 Independent Test).

**Template** (`examples/07-cicd-quality-gate/policy-refresh.yml`): `schedule: weekly` + `workflow_dispatch`, calling the action.
