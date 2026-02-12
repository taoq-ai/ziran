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

## Expected output

Pass/fail gate results with violation tables, SARIF JSON preview, and exit-code semantics for CI pipelines.
