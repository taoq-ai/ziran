# Data Model: Ground Truth Dataset & Business Impact

## New Entities

### Multi-Tenant SaaS Agent (vulnerable)

**File**: `benchmarks/ground_truth/agents/vulnerable_saas_multitenant.yaml`

- `agent_id`: vulnerable_saas_multitenant
- `framework`: langchain
- Tools: `get_account_data(account_id)`, `update_account(account_id, data)`, `list_invoices(account_id)`, `transfer_funds(from_id, to_id, amount)`
- No authorization checks — any user can access any account
- Known vulnerabilities: BOLA, BFLA

### Multi-Tenant SaaS Agent (safe)

**File**: `benchmarks/ground_truth/agents/safe_saas_multitenant.yaml`

- `agent_id`: safe_saas_multitenant
- `framework`: langchain
- Same tools but with per-request authorization validation and role-based scoping
- Guardrails: account_ownership_validation, role_based_access_control

### Bedrock Data Analyst Agent (vulnerable)

**File**: `benchmarks/ground_truth/agents/vulnerable_bedrock_analyst.yaml`

- `agent_id`: vulnerable_bedrock_analyst
- `framework`: bedrock
- Tools: `query_s3_bucket(bucket, key)`, `scan_dynamodb(table, filter)`, `send_report(email, content)`
- No data boundary enforcement

### Bedrock Data Analyst Agent (safe)

**File**: `benchmarks/ground_truth/agents/safe_bedrock_analyst.yaml`

- `agent_id`: safe_bedrock_analyst
- `framework`: bedrock
- Same tools with bucket allowlist and output sanitization

### AgentCore DevOps Agent (vulnerable)

**File**: `benchmarks/ground_truth/agents/vulnerable_agentcore_devops.yaml`

- `agent_id`: vulnerable_agentcore_devops
- `framework`: agentcore
- Tools: `deploy_service(service, env)`, `read_secrets(path)`, `execute_command(cmd)`, `update_config(key, value)`
- No environment isolation

### AgentCore DevOps Agent (safe)

**File**: `benchmarks/ground_truth/agents/safe_agentcore_devops.yaml`

- `agent_id`: safe_agentcore_devops
- `framework`: agentcore
- Same tools with environment isolation and secret access controls

## Modified Entities

### GroundTruthLabel (existing, extended)

**File**: `benchmarks/ground_truth/schema.py`

Add optional field:
- `expected_business_impact`: Optional list of BusinessImpact enum values expected for this scenario's attack category and severity

### Ground Truth Scenarios (new files)

**Authorization** (`benchmarks/ground_truth/scenarios/authorization/`):
- `tp_001_bola_cross_account.yaml` — Cross-account data access
- `tp_002_bfla_admin_tool.yaml` — Regular user invokes admin-only tool
- `tp_003_horizontal_escalation.yaml` — User A accesses User B's invoices
- `tp_004_vertical_escalation.yaml` — User escalates to admin role
- `tn_001_auth_rejects_cross_account.yaml` — Per-request auth blocks cross-account
- `tn_002_role_scoping_blocks_admin.yaml` — Role-based scoping prevents admin access

**LLM Judge** (`benchmarks/ground_truth/scenarios/llm_judge/`):
- `tp_001_subtle_exfil_encoded.yaml` — PII encoded in innocent response
- `tp_002_gradual_trust_escalation.yaml` — Multi-turn trust escalation
- `tp_003_indirect_injection_context.yaml` — Injection via retrieved context
- `tn_001_benign_multiturn.yaml` — Benign multi-turn conversation
- `tn_002_legitimate_aggregation.yaml` — Legitimate data aggregation

**Framework** (`benchmarks/ground_truth/scenarios/framework/`):
- `tp_001_bedrock_s3_exfil.yaml` — S3 data exfiltration via Bedrock agent
- `tn_001_bedrock_safe_analyst.yaml` — Safe Bedrock agent with allowlist
- `tp_002_agentcore_secret_leak.yaml` — Secret exposure via AgentCore agent
- `tn_002_agentcore_safe_devops.yaml` — Safe AgentCore agent with isolation
