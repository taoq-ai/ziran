# Remote Agent Scanning Guide

Step-by-step guide for scanning AI agents published over HTTPS using REST, OpenAI, MCP, or A2A protocols.

## Prerequisites

```bash
pip install ziran[all]   # All protocol support
# or
pip install ziran[a2a]   # Just A2A support
```

Set your API key as an environment variable:

```bash
export AGENT_API_KEY="your-key-here"
```

## Quick Start

```yaml
# target.yaml
name: "My Agent"
url: "https://my-agent.example.com"
protocol: auto
auth:
  type: bearer
  token_env: AGENT_API_KEY
```

```bash
ziran scan --target target.yaml
```

ZIRAN will auto-detect the protocol and run a standard scan (phases 1–6).

## Protocol-Specific Examples

### REST API

For agents with a custom HTTP API:

```yaml
# rest-target.yaml
name: "Custom REST Agent"
url: "https://api.example.com"
protocol: rest

rest:
  method: POST
  request_path: /api/chat
  message_field: message        # Field name for the user message
  response_field: response      # Field name in response JSON
  extra_body:                   # Additional fields in request body
    session_id: "test-session"
    model: "gpt-4"

auth:
  type: api_key
  token_env: API_KEY
  header_name: X-API-Key        # Custom header name
```

**How it works:** ZIRAN sends POST requests to `https://api.example.com/api/chat` with the message in the `message` field and reads the agent response from the `response` field.

### OpenAI-Compatible

For agents that implement the OpenAI Chat Completions API (including Azure OpenAI, Ollama, vLLM, LiteLLM):

```yaml
# openai-target.yaml
name: "OpenAI Agent"
url: "https://api.openai.com"
protocol: openai

auth:
  type: bearer
  token_env: OPENAI_API_KEY

rest:
  extra_body:
    model: "gpt-4"
```

**How it works:** ZIRAN sends requests to `/v1/chat/completions` using the standard OpenAI message format.

### MCP (Model Context Protocol)

For MCP-compliant tool servers:

```yaml
# mcp-target.yaml
name: "MCP Tool Server"
url: "https://mcp-server.example.com"
protocol: mcp

auth:
  type: bearer
  token_env: MCP_TOKEN
```

**How it works:** ZIRAN discovers available tools via the MCP protocol and tests each one for vulnerabilities.

**Protocol versions:** ZIRAN first sends `server/discover` with MCP 2026-07-28 in the per-request `_meta`. A server that supports 2026-07-28 gets every request in that shape, with the `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` headers. Any other answer means an older server. ZIRAN then sends `initialize` with 2025-11-25 (or the newest older version the server lists), uses the version the server answers (2025-11-25, 2025-06-18, 2025-03-26 or 2024-11-05) and keeps the session id the server hands out. A server that lists only versions ZIRAN does not know fails with an error that names them, and its vectors read unmeasured.

**Input requests:** when a tool call or prompt returns `resultType: "input_required"`, ZIRAN records each elicitation in the response metadata (`mcp_input_required`), declines it and retries the request once. It never opens the URL. A URL elicitation is added to the recorded reply, flagged when its host is not the MCP server's host.

A prompt goes to the server's `completion/complete` method. When the server rejects it, ZIRAN logs one warning and counts each prompt as an error, not a reply: the vector is unmeasured, the report reads INCOMPLETE and `ziran ci` fails when no vector was measured.

### A2A (Agent-to-Agent)

For agents implementing Google's A2A protocol:

```yaml
# a2a-target.yaml
name: "A2A Agent"
url: "https://a2a-agent.example.com"
protocol: a2a

auth:
  type: bearer
  token_env: A2A_TOKEN

a2a:
  agent_card_url: /.well-known/agent.json
  use_extended_card: false
  enable_streaming: false
```

**How it works:** ZIRAN fetches the Agent Card to discover skills, then sends A2A tasks to test each skill.

## Authentication

### Bearer Token

```yaml
auth:
  type: bearer
  token_env: MY_TOKEN   # Reads from $MY_TOKEN environment variable
```

### API Key in Custom Header

```yaml
auth:
  type: api_key
  token_env: MY_KEY
  header_name: X-API-Key
```

### Basic Auth

```yaml
auth:
  type: basic
  username: admin
  password_env: ADMIN_PASSWORD
```

### OAuth 2.0

```yaml
auth:
  type: oauth2
  client_id: my-client
  client_secret_env: OAUTH_SECRET
  token_url: https://auth.example.com/token
  scopes:
    - agent:read
    - agent:write
```

## TLS Configuration

```yaml
tls:
  verify: true                    # Verify server certificate
  client_cert: /path/to/cert.pem  # Mutual TLS
  client_key: /path/to/key.pem
```

!!! warning "Development only"

    Set `verify: false` only for local development. Never disable TLS verification in production scans.

## Retry & Timeout

```yaml
timeout: 30          # Request timeout in seconds
probe_delay: 0.5    # Seconds between discovery probes (0 disables)

retry:
  max_retries: 3
  backoff_factor: 0.5          # Exponential backoff multiplier
  retry_on: [429, 500, 502, 503, 504]  # HTTP status codes to retry
```

`probe_delay` spaces out the three discovery probes; the 0.5 s default adds about 1 s per discovery run compared with earlier releases, and `probe_delay: 0` restores back-to-back probes.

## Discovery Mode

Before running a full scan, discover what the agent can do:

```bash
ziran discover --target target.yaml
```

This runs Phase 1 (Reconnaissance) only, reporting discovered tools, skills, and capabilities.

## Python API

```python
import asyncio
from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.application.attacks.library import AttackLibrary
from ziran.infrastructure.adapters.http_agent_adapter import HttpAgentAdapter
from ziran.domain.entities.target import TargetConfig

config = TargetConfig.from_yaml("target.yaml")
adapter = HttpAgentAdapter(config)
scanner = AgentScanner(adapter=adapter, attack_library=AttackLibrary())

result = asyncio.run(scanner.run_campaign())
print(f"Vulnerabilities: {result.total_vulnerabilities}")
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Connection refused | Check URL is reachable and agent is running |
| 401 Unauthorized | Verify `token_env` is set in your environment |
| Protocol detection fails | Specify `protocol:` explicitly instead of `auto` |
| Timeout errors | Increase `timeout:` value or check agent performance |
| TLS certificate error | Set `tls.verify: false` for self-signed certs (dev only) |

## See Also

- [Remote Scanning Concepts](../concepts/remote-scanning.md) — Architecture and protocol details
- [A2A Protocol](../concepts/a2a-protocol.md) — Agent-to-Agent deep dive
