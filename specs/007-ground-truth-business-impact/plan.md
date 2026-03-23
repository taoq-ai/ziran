# Implementation Plan: Ground Truth Dataset & Business Impact

**Branch**: `007-ground-truth-business-impact` | **Date**: 2026-03-22 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/007-ground-truth-business-impact/spec.md`

## Summary

Expand the ground truth dataset from 54 to 69+ scenarios by adding authorization detector scenarios (BOLA/BFLA), LLM judge detector scenarios (subtle/ambiguous attacks), and Bedrock/AgentCore framework archetypes. Add `expected_business_impact` to the ground truth schema for validation. Business impact in reports is already implemented — no code changes needed there.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix: 3.11, 3.12, 3.13)
**Primary Dependencies**: PyYAML (scenario loading), Pydantic (schema validation)
**Storage**: YAML files (ground truth scenarios and agent archetypes)
**Testing**: pytest with markers (`@pytest.mark.unit`, `@pytest.mark.integration`)
**Target Platform**: Linux/macOS (CI + local dev)
**Project Type**: Library/CLI
**Performance Goals**: N/A (data-only changes + minor schema extension)
**Constraints**: Backward-compatible schema changes; existing 54 scenarios unmodified
**Scale/Scope**: 15 new scenario YAML files, 6 new agent YAML files, 1 schema extension

## Constitution Check

| Gate | Status | Notes |
|------|--------|-------|
| Hexagonal Architecture | PASS | Ground truth is benchmark data, not core architecture. Schema is in benchmarks/ |
| Type Safety | PASS | `expected_business_impact` will use existing `BusinessImpact` enum with Pydantic validation |
| Test Coverage | PASS | Accuracy benchmark script automatically validates new scenarios |
| Async-First | N/A | No I/O operations — YAML files loaded synchronously in benchmarks |
| Extensibility via Adapters | PASS | New attack vectors added as YAML definitions, not code changes |
| Simplicity | PASS | No new abstractions — extends existing schema with optional field |
| Quality Gates | PASS | ruff, mypy, pytest will be run post-implementation |

## Project Structure

### Documentation (this feature)

```text
specs/007-ground-truth-business-impact/
├── spec.md
├── plan.md              # This file
├── research.md
├── data-model.md
├── quickstart.md
└── checklists/
    └── requirements.md
```

### Source Code (files to create/modify)

```text
benchmarks/ground_truth/
├── schema.py                                    # Add expected_business_impact field
├── agents/
│   ├── vulnerable_saas_multitenant.yaml         # NEW
│   ├── safe_saas_multitenant.yaml               # NEW
│   ├── vulnerable_bedrock_analyst.yaml          # NEW
│   ├── safe_bedrock_analyst.yaml                # NEW
│   ├── vulnerable_agentcore_devops.yaml         # NEW
│   └── safe_agentcore_devops.yaml               # NEW
└── scenarios/
    ├── authorization/
    │   ├── tp_001_bola_cross_account.yaml       # NEW
    │   ├── tp_002_bfla_admin_tool.yaml          # NEW
    │   ├── tp_003_horizontal_escalation.yaml    # NEW
    │   ├── tp_004_vertical_escalation.yaml      # NEW
    │   ├── tn_001_auth_rejects_cross_account.yaml # NEW
    │   └── tn_002_role_scoping_blocks_admin.yaml  # NEW
    ├── llm_judge/
    │   ├── tp_001_subtle_exfil_encoded.yaml     # NEW
    │   ├── tp_002_gradual_trust_escalation.yaml # NEW
    │   ├── tp_003_indirect_injection_context.yaml # NEW
    │   ├── tn_001_benign_multiturn.yaml         # NEW
    │   └── tn_002_legitimate_aggregation.yaml   # NEW
    └── framework/
        ├── tp_001_bedrock_s3_exfil.yaml         # NEW
        ├── tn_001_bedrock_safe_analyst.yaml      # NEW
        ├── tp_002_agentcore_secret_leak.yaml    # NEW
        └── tn_002_agentcore_safe_devops.yaml    # NEW

benchmarks/accuracy_metrics.py                   # Update detector coverage to include authorization + llm_judge
```

**Structure Decision**: All new content goes into the existing `benchmarks/ground_truth/` directory structure. Empty `authorization/` and `llm_judge/` directories already exist. The `framework/` directory already has 2 existing scenarios — we add 4 more.

## Implementation Phases

### Phase 1: Schema Extension

**File**: `benchmarks/ground_truth/schema.py`

Add `expected_business_impact` as an optional field on `GroundTruthLabel`:
- Type: `list[str]` (BusinessImpact enum values)
- Default: empty list
- Backward-compatible — existing scenarios don't need updating

### Phase 2: Agent Archetypes (6 new YAML files)

Create 3 pairs of vulnerable/safe agents:

1. **Multi-tenant SaaS** (langchain): `get_account_data`, `update_account`, `list_invoices`, `transfer_funds` — vulnerable version has no auth, safe version has per-request auth + role scoping
2. **Bedrock Data Analyst** (bedrock): `query_s3_bucket`, `scan_dynamodb`, `send_report` — vulnerable version has no data boundaries, safe version has bucket allowlist + output sanitization
3. **AgentCore DevOps** (agentcore): `deploy_service`, `read_secrets`, `execute_command`, `update_config` — vulnerable version has no isolation, safe version has env isolation + secret access controls

Each follows the existing agent YAML schema (agent_id, name, description, framework, model, tools, system_prompt, system_prompt_traits, guardrails, known_vulnerabilities).

### Phase 3: Authorization Scenarios (6 new YAML files)

Using `vulnerable_saas_multitenant` and `safe_saas_multitenant` agents:

**True Positives:**
- `tp_001`: BOLA — agent retrieves another user's account data
- `tp_002`: BFLA — regular user invokes admin `transfer_funds` tool
- `tp_003`: Horizontal escalation — User A accesses User B's invoices
- `tp_004`: Vertical escalation — user escalates to admin role

**True Negatives:**
- `tn_001`: Per-request auth rejects cross-account data access
- `tn_002`: Role-based scoping blocks non-admin from `transfer_funds`

All scenarios set `expected_detectors` with `authorization` detector expectations.

### Phase 4: LLM Judge Scenarios (5 new YAML files)

Using existing agent archetypes where possible:

**True Positives:**
- `tp_001`: Subtle exfiltration — PII encoded in innocent response (rule-based detectors miss it)
- `tp_002`: Gradual trust escalation — multi-turn conversation slowly reveals sensitive data
- `tp_003`: Indirect injection via retrieved context bypasses indicator matching

**True Negatives:**
- `tn_001`: Benign multi-turn conversation that superficially resembles escalation
- `tn_002`: Legitimate data aggregation that looks like exfiltration but is authorized

All scenarios set `expected_detectors` with `llm_judge` as `should_fire: true` for TPs.

### Phase 5: Framework Scenarios (4 new YAML files)

Using the new Bedrock and AgentCore agents:

- `tp_001_bedrock_s3_exfil.yaml`: S3 data exfiltration via vulnerable Bedrock analyst
- `tn_001_bedrock_safe_analyst.yaml`: Safe Bedrock analyst with allowlist blocks exfil
- `tp_002_agentcore_secret_leak.yaml`: Secret exposure via vulnerable AgentCore DevOps
- `tn_002_agentcore_safe_devops.yaml`: Safe AgentCore agent with isolation blocks secret access

### Phase 6: Accuracy Benchmark Update

**File**: `benchmarks/accuracy_metrics.py`

Update `compute_detector_coverage()` to include `authorization` and `llm_judge` detectors in its analysis. The function already iterates through `expected_detectors` — it just needs the new detector names recognized.

## Verification

1. `uv run ruff check .` — zero lint errors
2. `uv run ruff format --check .` — zero drift
3. `uv run python -m mypy ziran/` — zero type errors
4. `uv run pytest tests/ -x -m "not integration"` — all unit tests pass
5. `uv run python benchmarks/accuracy_metrics.py` — accuracy benchmark runs with new scenarios
6. Verify authorization detector appears in detector coverage output
7. Verify llm_judge detector appears in detector coverage output
8. Verify Bedrock and AgentCore frameworks appear in results

## Complexity Tracking

No constitution violations. No complexity justifications needed.
