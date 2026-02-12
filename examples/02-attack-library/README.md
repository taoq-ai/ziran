# Attack Library

Browse and filter the built-in library of 40+ attack vectors, and load custom vectors from YAML.

## What it demonstrates

- Loading the built-in attack library
- Category breakdown and vector counts
- Filtering by phase, OWASP category, severity
- Multi-criteria search API
- Loading custom attack vectors from a YAML file

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
| [main.py](main.py) | Example script — explores the attack library |
| [custom_vector.yaml](custom_vector.yaml) | Sample custom attack vector definition |
| [run.sh](run.sh) | One-command launcher |

## Expected output

Rich tables showing vectors grouped by category, phase, OWASP mapping, and severity — plus the custom vector loaded from YAML.
