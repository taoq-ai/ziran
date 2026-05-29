# Policy-refresh automation

`ziran export-policy` renders guardrail policy bundles (OPA/Rego, Cedar, NeMo Colang, Invariant Labs) from scan findings. Run once, those bundles drift stale as the attack library or your agent changes. The **export-policy composite Action** keeps them fresh: it re-scans, regenerates the bundle, and opens (or updates) a single PR when the result differs from what is committed.

## Quick start

Copy [`examples/07-cicd-quality-gate/policy-refresh.yml`](../../examples/07-cicd-quality-gate/policy-refresh.yml) into `.github/workflows/`:

```yaml
name: Policy Refresh
on:
  schedule: [{ cron: "0 6 * * 1" }]   # weekly
  workflow_dispatch: {}
concurrency:
  group: ziran-policy-refresh         # overlapping runs can't open competing PRs
  cancel-in-progress: true
permissions:
  contents: write
  pull-requests: write
jobs:
  refresh:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.13" }
      - run: python -m pip install ziran
      - uses: taoq-ai/ziran/.github/actions/export-policy@v0
        with:
          target: target.yaml
          out-dir: policies/
          target-formats: rego,cedar,nemo,invariant
          reviewer-team: secops
```

## Inputs

| Input | Default | Purpose |
|-------|---------|---------|
| `target` | — | YAML target config to scan. |
| `result-json` | — | Pre-existing campaign result JSON; skips the scan (offline mode). Provide `target` **or** `result-json`. |
| `out-dir` | `policies` | Committed bundle directory (holds only generated policy files). |
| `target-formats` | `rego,cedar,nemo,invariant` | Comma list — scope which formats to regenerate. |
| `severity-floor` | `medium` | Minimum severity to include. |
| `fail-on-diff` | `false` | Fail the run on drift instead of opening a PR. |
| `branch` | `ziran/policy-refresh` | Fixed head branch for the single long-lived refresh PR. |
| `reviewer-team` | — | Team/user slug to request review from. |
| `token` | `github.token` | Token for git push and PR operations. |

## Behaviour

- **No drift** → no PR, run succeeds (`changed=false`).
- **Drift + `fail-on-diff: false`** → regenerated files are synced into `out-dir` (stale files removed) and committed to the fixed `ziran/policy-refresh` branch; a PR is opened if none exists for that branch, otherwise the existing one is updated. The PR is labelled `policy-refresh` and the reviewer team is requested.
- **Drift + `fail-on-diff: true`** → the run fails and prints the diff; no PR is opened. Use this for hard enforcement.

The fixed head branch means a single refresh PR is maintained regardless of whether your base branch uses squash or merge-commit merges, and the workflow's `concurrency` group prevents overlapping scheduled runs from racing.

## Scoping formats

`target-formats` regenerates only the listed formats — e.g. `rego,cedar` to keep just OPA/Rego and Cedar bundles current.

## Notes

- The Action assumes the repo is already checked out and `ziran` is installed (see the template's install step).
- For offline/keyless runs (or to re-render a prior scan), pass `result-json` instead of `target`.
