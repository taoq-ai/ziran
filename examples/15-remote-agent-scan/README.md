# Example: Scanning Remote Agents

This example demonstrates how to scan AI agents published over HTTPS
using ZIRAN's remote scanning capabilities. It includes a **runnable
vulnerable demo server** you can scan locally — no external API keys required.

## Run It Yourself (< 2 minutes)

### Prerequisites

```bash
cd examples
uv sync --extra remote          # installs fastapi, uvicorn & ziran
```

### Option A — one command

```bash
cd examples/15-remote-agent-scan
bash run.sh
```

This starts the vulnerable demo server, runs the full ZIRAN scan, and
saves reports to `reports/`.

### Option B — step by step

```bash
# Terminal 1 — start the vulnerable agent
cd examples/15-remote-agent-scan
uv run --project .. --extra remote uvicorn vulnerable_server:app --port 8899

# Terminal 2 — scan it
cd examples/15-remote-agent-scan
uv run --project .. --extra remote python main.py      # Python API
# OR
uv run --project .. --extra remote ziran scan --target target-local.yaml  # CLI
```

### What to expect

The demo server (`vulnerable_server.py`) is a FastAPI app that implements
the OpenAI chat completions API with **deliberate** security anti-patterns:

| Vulnerability | How it's exposed |
|---|---|
| System prompt leakage | Hands over the full system prompt on request |
| PII disclosure | Returns employee SSNs, salaries without auth checks |
| Credential exposure | Leaks DB passwords and API keys from config |
| Unguarded SQL execution | Executes arbitrary SQL with no validation |
| Unrestricted email | Sends emails to any address without confirmation |

ZIRAN's scanner will discover these via multi-phase probing and report
them with severity scores and remediation guidance.

---

## Supported Protocols

| Protocol | Config | Description |
|----------|--------|-------------|
| Local demo | `target-local.yaml` | **Runnable** — the included vulnerable server |
| REST | `target-rest.yaml` | Generic REST API endpoint |
| OpenAI | `target-openai.yaml` | OpenAI-compatible chat completions |
| MCP | `target-mcp.yaml` | Model Context Protocol (JSON-RPC) |
| A2A | `target-a2a.yaml` | Google Agent-to-Agent protocol |

## CLI Quick Reference

```bash
# Scan an OpenAI-compatible agent
ziran scan --target target-openai.yaml

# Scan an A2A agent with comprehensive coverage
ziran scan --target target-a2a.yaml --coverage comprehensive

# Discover capabilities without attacking
ziran discover --target target-a2a.yaml

# Override protocol auto-detection
ziran scan --target target-rest.yaml --protocol rest

# Run specific phases only
ziran scan --target target-openai.yaml --phases reconnaissance trust_building
```

## Configuration

Each YAML target config file specifies:

- **url**: The agent's HTTPS endpoint
- **protocol**: Protocol type (`rest`, `openai`, `mcp`, `a2a`, or `auto`)
- **auth**: Authentication configuration (bearer, api_key, basic, oauth2)
- **tls**: TLS/certificate settings
- **retry**: Retry policy for transient failures
- **timeout**: Request timeout in seconds
- **headers**: Additional HTTP headers

### Environment Variables

Sensitive values like API keys can reference environment variables:

```yaml
auth:
  type: bearer
  env_var: MY_API_KEY  # reads from $MY_API_KEY at runtime
```

### Protocol-Specific Settings

#### REST

```yaml
rest:
  method: POST
  request_path: /api/chat
  message_field: message
  response_field: response.text
```

#### A2A

```yaml
a2a:
  agent_card_url: https://agent.example.com/.well-known/agent-card.json
  blocking: true
  enable_streaming: false
```

## Writing Custom Attack Vectors

You can create protocol-specific attack vectors using the `protocol_filter` field:

```yaml
vectors:
  - id: my_a2a_attack
    name: Custom A2A Attack
    category: prompt_injection
    target_phase: payload_delivery
    severity: high
    protocol_filter: [a2a]  # Only runs against A2A agents
    prompts:
      - template: "..."
```

Vectors without `protocol_filter` run against all protocols.
