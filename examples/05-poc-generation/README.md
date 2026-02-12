# PoC Generation

Generate proof-of-concept exploit scripts from attack results — useful for reproducing, validating, and sharing vulnerability findings.

## What it demonstrates

- Creating `AttackResult` objects programmatically
- Generating a Python PoC script
- Generating a cURL PoC script
- Generating a Markdown reproduction guide
- Using `generate_all()` from a `CampaignResult`

## Prerequisites

- Python 3.11+
- `pip install ziran`

No API keys required — uses synthetic attack results.

## Run

```bash
./run.sh
# or
uv run python main.py
```

## Files

| File | Purpose |
|------|---------|
| [main.py](main.py) | Example script — generates PoC scripts |
| [run.sh](run.sh) | One-command launcher |

## Expected output

Syntax-highlighted previews of generated Python, cURL, and Markdown PoC scripts, plus a summary of all files generated from a campaign result. Temporary files are cleaned up automatically.
