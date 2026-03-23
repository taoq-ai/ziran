# Tasks: Ground Truth Dataset & Business Impact

**Input**: Design documents from `/specs/007-ground-truth-business-impact/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, quickstart.md

**Tests**: Not explicitly requested in the specification. Tests are omitted; the accuracy benchmark script (`benchmarks/accuracy_metrics.py`) automatically validates new scenarios.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

---

## Phase 1: Setup (Schema Extension)

**Purpose**: Extend the ground truth schema to support business impact validation

- [x] T001 Add `expected_business_impact` optional field to `GroundTruthLabel` in `benchmarks/ground_truth/schema.py`

**Checkpoint**: Schema extended — all existing scenarios still load correctly

---

## Phase 2: User Story 1 — Authorization Detector Ground Truth Scenarios (Priority: P1) 🎯 MVP

**Goal**: Provide 6 ground truth scenarios (4 TP + 2 TN) for the authorization detector so precision and recall can be measured.

**Independent Test**: Run `uv run python benchmarks/accuracy_metrics.py` and confirm the authorization detector appears in results with measurable precision and recall scores.

### Agent Archetypes for US1

- [x] T002 [P] [US1] Create vulnerable multi-tenant SaaS agent archetype in `benchmarks/ground_truth/agents/vulnerable_saas_multitenant.yaml`
- [x] T003 [P] [US1] Create safe multi-tenant SaaS agent archetype in `benchmarks/ground_truth/agents/safe_saas_multitenant.yaml`

### Authorization Scenarios for US1

- [x] T004 [P] [US1] Create BOLA cross-account access TP scenario in `benchmarks/ground_truth/scenarios/authorization/tp_001_bola_cross_account.yaml`
- [x] T005 [P] [US1] Create BFLA admin tool invocation TP scenario in `benchmarks/ground_truth/scenarios/authorization/tp_002_bfla_admin_tool.yaml`
- [x] T006 [P] [US1] Create horizontal escalation TP scenario in `benchmarks/ground_truth/scenarios/authorization/tp_003_horizontal_escalation.yaml`
- [x] T007 [P] [US1] Create vertical escalation TP scenario in `benchmarks/ground_truth/scenarios/authorization/tp_004_vertical_escalation.yaml`
- [x] T008 [P] [US1] Create auth-rejects-cross-account TN scenario in `benchmarks/ground_truth/scenarios/authorization/tn_001_auth_rejects_cross_account.yaml`
- [x] T009 [P] [US1] Create role-scoping-blocks-admin TN scenario in `benchmarks/ground_truth/scenarios/authorization/tn_002_role_scoping_blocks_admin.yaml`

**Checkpoint**: Authorization detector has 6 scenarios — accuracy benchmark produces precision/recall for it

---

## Phase 3: User Story 2 — LLM Judge Detector Ground Truth Scenarios (Priority: P1)

**Goal**: Provide 5 ground truth scenarios (3 TP + 2 TN) for the LLM judge detector designed around subtle/ambiguous attacks.

**Independent Test**: Run `uv run python benchmarks/accuracy_metrics.py` and confirm the LLM judge detector appears in results with measurable precision and recall scores.

### LLM Judge Scenarios for US2

- [x] T010 [P] [US2] Create subtle exfiltration with encoded PII TP scenario in `benchmarks/ground_truth/scenarios/llm_judge/tp_001_subtle_exfil_encoded.yaml`
- [x] T011 [P] [US2] Create gradual trust escalation TP scenario in `benchmarks/ground_truth/scenarios/llm_judge/tp_002_gradual_trust_escalation.yaml`
- [x] T012 [P] [US2] Create indirect injection via context TP scenario in `benchmarks/ground_truth/scenarios/llm_judge/tp_003_indirect_injection_context.yaml`
- [x] T013 [P] [US2] Create benign multi-turn conversation TN scenario in `benchmarks/ground_truth/scenarios/llm_judge/tn_001_benign_multiturn.yaml`
- [x] T014 [P] [US2] Create legitimate data aggregation TN scenario in `benchmarks/ground_truth/scenarios/llm_judge/tn_002_legitimate_aggregation.yaml`

**Checkpoint**: LLM judge detector has 5 scenarios — accuracy benchmark produces precision/recall for it

---

## Phase 4: User Story 3 — Bedrock and AgentCore Agent Archetypes (Priority: P2)

**Goal**: Add Bedrock and AgentCore framework archetypes with ground truth scenarios so framework-specific detection gaps can be identified.

**Independent Test**: Verify new agent YAML files load correctly and accuracy benchmark includes findings attributed to Bedrock and AgentCore frameworks.

### Agent Archetypes for US3

- [x] T015 [P] [US3] Create vulnerable Bedrock data analyst agent in `benchmarks/ground_truth/agents/vulnerable_bedrock_analyst.yaml`
- [x] T016 [P] [US3] Create safe Bedrock data analyst agent in `benchmarks/ground_truth/agents/safe_bedrock_analyst.yaml`
- [x] T017 [P] [US3] Create vulnerable AgentCore DevOps agent in `benchmarks/ground_truth/agents/vulnerable_agentcore_devops.yaml`
- [x] T018 [P] [US3] Create safe AgentCore DevOps agent in `benchmarks/ground_truth/agents/safe_agentcore_devops.yaml`

### Framework Scenarios for US3

- [x] T019 [P] [US3] Create Bedrock S3 exfiltration TP scenario in `benchmarks/ground_truth/scenarios/framework/tp_001_bedrock_s3_exfil.yaml`
- [x] T020 [P] [US3] Create safe Bedrock analyst TN scenario in `benchmarks/ground_truth/scenarios/framework/tn_001_bedrock_safe_analyst.yaml`
- [x] T021 [P] [US3] Create AgentCore secret leak TP scenario in `benchmarks/ground_truth/scenarios/framework/tp_002_agentcore_secret_leak.yaml`
- [x] T022 [P] [US3] Create safe AgentCore DevOps TN scenario in `benchmarks/ground_truth/scenarios/framework/tn_002_agentcore_safe_devops.yaml`

**Checkpoint**: Bedrock and AgentCore frameworks each have agent archetypes and at least 1 ground truth scenario

---

## Phase 5: User Story 4 — Business Impact in Ground Truth (Priority: P2)

**Goal**: Ensure `expected_business_impact` is populated on all new scenarios for accuracy benchmark validation. Business impact in reports is already implemented (R4 research confirms no code changes needed for FR-007/FR-008).

**Independent Test**: Run the accuracy benchmark and verify business impact values are present on new scenarios.

### Implementation for US4

- [x] T023 [US4] Verify all new scenarios (T004–T022) include `expected_business_impact` field with correct values per attack category and severity

**Checkpoint**: All new scenarios include expected business impact — no code changes needed for reports

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Accuracy benchmark update and quality validation

- [x] T024 Update detector coverage in `benchmarks/accuracy_metrics.py` to include `authorization` and `llm_judge` detectors
- [x] T025 Run quality gates: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`
- [x] T026 Run accuracy benchmark: `uv run python benchmarks/accuracy_metrics.py` and verify all 15 new scenarios load
- [x] T027 Run unit tests: `uv run pytest tests/ -x -m "not integration"` — all pass, no regressions

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1 (Setup)**: No dependencies — start immediately
- **Phase 2 (US1)**: Depends on Phase 1 (schema must have `expected_business_impact`)
- **Phase 3 (US2)**: Depends on Phase 1 only — can run in parallel with Phase 2
- **Phase 4 (US3)**: Depends on Phase 1 only — can run in parallel with Phases 2–3
- **Phase 5 (US4)**: Depends on Phases 2–4 (all scenarios must exist to verify business impact)
- **Phase 6 (Polish)**: Depends on all previous phases

### User Story Dependencies

- **US1 (Authorization)**: Independent — requires its own SaaS agent archetypes (T002–T003)
- **US2 (LLM Judge)**: Independent — uses existing agent archetypes where possible
- **US3 (Frameworks)**: Independent — requires its own Bedrock/AgentCore archetypes (T015–T018)
- **US4 (Business Impact)**: Cross-cutting — verifies all new scenarios have business impact

### Within Each User Story

- Agent archetypes MUST be created before scenarios that reference them
- All scenario YAML files within a story are independent and can be created in parallel
- Core implementation before verification

### Parallel Opportunities

- T002–T003 (SaaS agents) can run in parallel
- T004–T009 (authorization scenarios) can all run in parallel after T002–T003
- T010–T014 (LLM judge scenarios) can all run in parallel (independent of US1)
- T015–T018 (framework agents) can all run in parallel
- T019–T022 (framework scenarios) can all run in parallel after T015–T018
- US1, US2, and US3 can proceed in parallel after Phase 1

---

## Parallel Example: User Story 1

```bash
# Create both SaaS agent archetypes in parallel:
Task T002: "Create vulnerable SaaS agent in agents/vulnerable_saas_multitenant.yaml"
Task T003: "Create safe SaaS agent in agents/safe_saas_multitenant.yaml"

# Then create all 6 authorization scenarios in parallel:
Task T004: "BOLA cross-account TP in scenarios/authorization/tp_001_bola_cross_account.yaml"
Task T005: "BFLA admin tool TP in scenarios/authorization/tp_002_bfla_admin_tool.yaml"
Task T006: "Horizontal escalation TP in scenarios/authorization/tp_003_horizontal_escalation.yaml"
Task T007: "Vertical escalation TP in scenarios/authorization/tp_004_vertical_escalation.yaml"
Task T008: "Auth rejects cross-account TN in scenarios/authorization/tn_001_auth_rejects_cross_account.yaml"
Task T009: "Role scoping blocks admin TN in scenarios/authorization/tn_002_role_scoping_blocks_admin.yaml"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Schema extension (T001)
2. Complete Phase 2: Authorization scenarios (T002–T009)
3. **STOP and VALIDATE**: Run accuracy benchmark — authorization detector has precision/recall
4. Deploy/demo if ready

### Incremental Delivery

1. Phase 1 → Schema ready
2. Add US1 (authorization) → 6 scenarios → Validate independently
3. Add US2 (LLM judge) → 5 more scenarios → Validate independently
4. Add US3 (frameworks) → 4 more scenarios + 4 agents → Validate independently
5. US4 verification + Polish → All 15 scenarios with business impact → Full validation

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story is independently completable and testable
- T023 is a verification task — `expected_business_impact` should be included inline when creating each scenario (T004–T022)
- No code changes needed for reports (FR-007/FR-008 already implemented per R4)
- Total: 27 tasks, 15 new YAML scenarios, 6 new agent archetypes, 1 schema extension
