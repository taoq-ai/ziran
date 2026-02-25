# AgentCore Scan

Scan an agent deployed on **Amazon Bedrock AgentCore** using ZIRAN's
in-process `AgentCoreAdapter` — directly invokes the agent's entrypoint
function without going through HTTP.

## Architecture

```
ZIRAN Scanner
    │
    ▼
AgentCoreAdapter
    │
    ├──► option A: direct entrypoint callable
    │       my_agent(prompt) → response
    │
    └──► option B: BedrockAgentCoreApp
            app = BedrockAgentCoreApp()
            @app.entrypoint
            def handler(prompt): ...
```

## What it demonstrates

- Using the **`AgentCoreAdapter`** to scan AgentCore-deployed agents
- Two integration patterns: raw callable and `BedrockAgentCoreApp`
- In-process scanning (no HTTP, no deployed endpoint needed)
- Capability discovery via AgentCore tool introspection
- Combining with the LLM judge for enhanced detection

## Prerequisites

- Python 3.11+
- `pip install ziran[agentcore]` (or `uv pip install bedrock-agentcore boto3`)

### Option A: Scan without AgentCore SDK (mock agent)

No additional setup needed — the example includes a mock agent.

```bash
uv run python main.py
```

### Option B: Scan your own AgentCore agent

```bash
# Your agent module must expose an entrypoint or BedrockAgentCoreApp
uv run python main.py --agent-module my_agent --entrypoint handler
```

## Run

```bash
./run.sh
# or
uv run python main.py
```

### With LLM judge

```bash
export OPENAI_API_KEY=sk-...
uv run python main.py --llm-judge
```

## Files

| File | Purpose |
|------|---------|
| [main.py](main.py) | Mock agent, AgentCoreAdapter setup, scan execution |
| [run.sh](run.sh) | One-command launcher |

## Expected results

The included mock agent has intentional vulnerabilities (oversharing
employee data, executing raw queries). Expect ZIRAN to find 2–5
vulnerabilities depending on scan coverage.
