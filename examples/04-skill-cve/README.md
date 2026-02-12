# Skill CVE Database

Check agent tools against a curated database of known vulnerabilities in popular agent tools.

## What it demonstrates

- Browsing the seed CVE database (15 entries)
- Filtering CVEs by framework and severity
- Checking agent capabilities against known CVEs
- Submitting a custom CVE entry

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
| [main.py](main.py) | Example script — queries and extends the CVE database |
| [run.sh](run.sh) | One-command launcher |

## Expected output

Rich tables listing known CVEs, filtered views by framework/severity, capability match results, and a successfully submitted custom CVE.
