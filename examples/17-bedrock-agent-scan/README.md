# Bedrock Agent Scan

Scan an Amazon Bedrock Agent using ZIRAN's native `BedrockAdapter` — in-process
invocation via the AWS SDK (no HTTP server required).

## Architecture

```
ZIRAN Scanner
    │
    ▼
BedrockAdapter (boto3)
    │
    ▼
AWS Bedrock Agents Runtime
    │
    ▼
Your Bedrock Agent (agent_id + alias)
```

## What it demonstrates

- Using the **`BedrockAdapter`** for in-process Bedrock Agent scanning
- Configuring agent ID, alias, and AWS region via a YAML config file
- Capability discovery via Bedrock Agent action groups
- Running a multi-phase security scan against a deployed Bedrock Agent
- Combining with the LLM judge (optional) for enhanced detection

## Prerequisites

- Python 3.11+
- `pip install ziran[bedrock]` (or `uv pip install boto3`)
- A deployed Bedrock Agent with an agent ID and alias
- AWS credentials configured (`aws configure` or environment variables)

```bash
# Required
export AWS_DEFAULT_REGION=us-east-1      # or your agent's region
# AWS credentials via any standard method:
#   - AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY
#   - AWS_PROFILE
#   - IAM role (EC2/ECS/Lambda)
```

## Run

```bash
# Edit bedrock-agent.yaml with your agent ID first!
./run.sh
# or
uv run python main.py --config bedrock-agent.yaml
```

### With LLM judge

```bash
export OPENAI_API_KEY=sk-...
uv run python main.py --config bedrock-agent.yaml --llm-judge
```

## Files

| File | Purpose |
|------|---------|
| [main.py](main.py) | Loads config, creates BedrockAdapter, runs scan |
| [bedrock-agent.yaml](bedrock-agent.yaml) | Agent configuration (edit with your agent ID) |
| [run.sh](run.sh) | One-command launcher |

## Expected results

Results depend on the target agent's security posture. Bedrock Agents
with guardrails enabled typically show strong refusal patterns. Agents
without guardrails may be vulnerable to prompt injection, data
exfiltration, and unauthorized tool execution.
