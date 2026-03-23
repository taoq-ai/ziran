# Quickstart: Ground Truth Dataset & Business Impact

## What Changed

1. **6 authorization scenarios** (4 TP + 2 TN) with multi-tenant SaaS agent archetype
2. **5 LLM judge scenarios** (3 TP + 2 TN) for subtle/ambiguous attacks
3. **4 framework scenarios** (2 TP + 2 TN) with Bedrock and AgentCore archetypes
4. **6 new agent archetypes** (3 vulnerable + 3 safe) for SaaS, Bedrock, and AgentCore
5. **`expected_business_impact`** field added to ground truth schema (optional, backward-compatible)

## Verification

```bash
# Validate all ground truth scenarios load correctly
uv run python benchmarks/accuracy_metrics.py

# Run the full accuracy benchmark and check new detectors appear
uv run python benchmarks/accuracy_metrics.py --json /tmp/accuracy.json
cat /tmp/accuracy.json | python -m json.tool | grep -A5 "authorization\|llm_judge"

# Run unit tests
uv run pytest tests/ -x -m "not integration"

# Check linting and types
uv run ruff check .
uv run python -m mypy ziran/
```

## New Agent Archetypes

| Agent | Framework | Variant | Use Case |
|-------|-----------|---------|----------|
| vulnerable_saas_multitenant | langchain | Vulnerable | Multi-tenant SaaS with no auth checks |
| safe_saas_multitenant | langchain | Safe | Same with per-request auth validation |
| vulnerable_bedrock_analyst | bedrock | Vulnerable | Cloud data analyst with S3/DynamoDB |
| safe_bedrock_analyst | bedrock | Safe | Same with bucket allowlist |
| vulnerable_agentcore_devops | agentcore | Vulnerable | DevOps automation with secrets access |
| safe_agentcore_devops | agentcore | Safe | Same with environment isolation |
