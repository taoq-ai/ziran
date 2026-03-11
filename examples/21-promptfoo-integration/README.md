# Example 21: Promptfoo Integration

Run ZIRAN security analysis through [Promptfoo](https://www.promptfoo.dev/) for configuration-driven agent security testing.

## Prerequisites

```bash
# Install ZIRAN
pip install ziran

# Install Promptfoo
npm install -g promptfoo
```

## Quick Start

1. Start the deliberately vulnerable demo server:

```bash
cd examples/15-remote-agent-scan
uvicorn vulnerable_server:app --port 8899
```

2. Run the default security evaluation:

```bash
cd examples/21-promptfoo-integration
promptfoo eval
```

3. View results in the browser:

```bash
promptfoo view
```

## Example Configurations

This example includes several Promptfoo configs targeting different ZIRAN features:

| Config | Description | Run Command |
|--------|-------------|-------------|
| `promptfooconfig.yaml` | Quick overview — prompt injection, data exfil, authz | `promptfoo eval` |
| `configs/basic-security.yaml` | Prompt injection & system prompt protection | `promptfoo eval -c configs/basic-security.yaml` |
| `configs/authorization-bypass.yaml` | BOLA/BFLA authorization bypass testing | `promptfoo eval -c configs/authorization-bypass.yaml` |
| `configs/data-exfiltration.yaml` | Data leakage via direct, email, SQL channels | `promptfoo eval -c configs/data-exfiltration.yaml` |
| `configs/full-campaign.yaml` | Full multi-phase ZIRAN campaign with trust scoring | `promptfoo eval -c configs/full-campaign.yaml` |

## How It Works

- `promptfooconfig.yaml` — Defines test cases (attack prompts) and assertions
- `ziran_provider.py` — Thin wrapper around `ziran.integrations.promptfoo.provider`
- `ziran_assertions.py` — Thin wrapper around `ziran.integrations.promptfoo.assertions`

Each test case sends an attack prompt to your agent through ZIRAN's `HttpAgentAdapter`. The response is evaluated using both Promptfoo's built-in assertions (`not-contains`, etc.) and ZIRAN's custom assertions (`blocked_indicators`, `max_tool_calls`, etc.).

## Provider Configuration

```yaml
providers:
  - id: "file://ziran_provider.py"
    config:
      target_url: "http://your-agent:8000/chat"  # Your agent's endpoint
      protocol: "openai"                          # openai, rest, mcp, a2a, auto
      success_indicators:                         # Terms suggesting attack success
        - "password"
        - "secret"
      full_campaign: false                        # Set true for multi-phase scan
```

## Custom Assertions

ZIRAN assertions check:

| Config Key | Description |
|---|---|
| `max_vulnerabilities` | Fail if vulnerability count exceeds threshold |
| `min_trust_score` | Fail if trust score below threshold (0.0-1.0) |
| `max_tool_calls` | Fail if agent made tool calls (suggests exploitation) |
| `blocked_indicators` | Fail if any of these terms appear in output |

## Full Campaign Mode

For comprehensive scanning (all attack phases), set `full_campaign: true` in the provider config. This runs ZIRAN's complete multi-phase campaign instead of individual prompts. See `configs/full-campaign.yaml` for an example.

## CI/CD Usage

This assumes your repo contains the Promptfoo config files
(`promptfooconfig.yaml`, `ziran_provider.py`, `ziran_assertions.py`).
Promptfoo reads `promptfooconfig.yaml` which references
`file://ziran_provider.py` as the provider — that file imports
`ziran.integrations.promptfoo.provider` internally.

```yaml
# .github/workflows/security.yml
name: Agent Security
on: [push]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - uses: actions/setup-node@v4

      - run: pip install ziran
      - run: npm install -g promptfoo

      # promptfoo reads promptfooconfig.yaml → file://ziran_provider.py → ziran
      - run: promptfoo eval --no-cache
```

For running ZIRAN directly without Promptfoo, see the
[CI/CD Integration guide](https://taoq-ai.github.io/ziran/guides/cicd-integration/).
