# CI/CD Quality Gate & SARIF Reports

Evaluate campaign results against configurable quality-gate thresholds and produce SARIF reports for GitHub Code Scanning.

## What it demonstrates

- Default quality-gate evaluation (zero critical tolerance)
- Custom quality-gate config via YAML
- Programmatic `QualityGateConfig`
- SARIF report generation and inspection
- Exit-code semantics for pipeline integration

## Prerequisites

- Python 3.11+
- `pip install ziran`

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
| [main.py](main.py) | Example script — quality gate + SARIF demos |
| [gate_config.yaml](gate_config.yaml) | Lenient quality-gate config (1 critical allowed) |
| [run.sh](run.sh) | One-command launcher |

## GitHub Action

ZIRAN ships as a GitHub Action for seamless CI/CD integration.
See [`ziran-scan.yml`](ziran-scan.yml) for a ready-to-copy workflow that demonstrates:

- **Live scan** — runs the full attack suite against your agent (requires LLM API keys)
- **Offline CI gate** — evaluates a pre-existing campaign result JSON (no keys needed)

Usage:

```yaml
- uses: taoq-ai/ziran@v1
  with:
    command: ci
    result-file: scan_results/campaign_report.json
    gate-config: gate_config.yaml
```

The action automatically produces SARIF reports for GitHub Code Scanning,
emits annotations on the PR, and writes a step summary.

Credentials are **provider-agnostic** — set the env var your agent framework
needs (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, etc.)
at the workflow, job, or step level.

## Expected output

Pass/fail gate results with violation tables, SARIF JSON preview, and exit-code semantics for CI pipelines.
