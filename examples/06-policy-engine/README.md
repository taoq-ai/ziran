# Policy Engine

Evaluate scan results against organisational security policies — built-in defaults or custom YAML rules.

## What it demonstrates

- Using the built-in default policy
- Evaluating a *safe* campaign result (should PASS)
- Evaluating a *vulnerable* campaign result (should FAIL)
- Writing and loading a custom YAML policy with stricter thresholds
- Understanding errors vs warnings in policy verdicts

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
| [main.py](main.py) | Example script — runs policy evaluations |
| [strict_policy.yaml](strict_policy.yaml) | Custom enterprise policy with zero-tolerance rules |
| [run.sh](run.sh) | One-command launcher |

## Expected output

Pass/fail verdicts with violation details — the safe campaign passes the default policy, the vulnerable one fails, and even the safe campaign may fail the strict enterprise policy.
