# Research: Ground Truth Dataset & Business Impact

## R1: Authorization Scenario Design

**Decision**: Create a multi-tenant SaaS agent archetype (`vulnerable_saas_multitenant`) with account-scoped tools and no authorization checks. Pair with a safe variant (`safe_saas_multitenant`) that has per-request authorization validation.

**Rationale**: The AuthorizationDetector checks for ID substitution, admin tool invocation, and PII patterns. BOLA scenarios need cross-account ID substitution; BFLA scenarios need role-scoped tool invocation. A multi-tenant SaaS agent naturally exposes both patterns.

**Scenario count**: 4 TP (BOLA cross-account, BFLA admin tool, horizontal escalation, vertical escalation) + 2 TN (per-request auth rejects cross-account, role-based scoping blocks admin tools) = 6 scenarios.

## R2: LLM Judge Scenario Design

**Decision**: Create scenarios where rule-based detectors (Refusal, Indicator, SideEffect) are expected to be ambiguous or miss the attack, requiring the LLM judge for correct classification. Use existing agent archetypes where possible.

**Rationale**: The LLMJudgeDetector uses AI evaluation with optional StrongREJECT-style quality scoring. Its value is in catching subtle attacks that bypass keyword matching. Scenarios should include: steganographic exfiltration, gradual trust escalation, and indirect injection via retrieved context.

**Scenario count**: 3 TP (subtle exfil, gradual escalation, indirect injection) + 2 TN (benign multi-turn, legitimate data aggregation) = 5 scenarios.

## R3: Bedrock & AgentCore Archetypes

**Decision**: Create one vulnerable and one safe archetype for each framework (4 total agents, 4 scenarios minimum). Bedrock agent: cloud data analyst with S3/DynamoDB tools. AgentCore agent: DevOps automation with deployment tools.

**Rationale**: These frameworks have dedicated adapters but zero test coverage. The agent tools should expose realistic attack surfaces for each framework's typical use case.

**Scenario count**: 2 TP + 2 TN = 4 scenarios (1 per agent variant).

## R4: Business Impact in Reports

**Decision**: Business impact is already fully implemented — `get_business_impacts()` populates `AttackResult.business_impact`, and the Markdown report already renders a Business Impact Summary table. The JSON report already serializes the field. No code changes needed for FR-007 and FR-008.

**Rationale**: Exploration confirmed the business impact table exists in `reports.py` lines 242-281 and `business_impact` is populated in `attack_executor.py` line 114. The only gap is adding `expected_business_impact` to ground truth scenarios for validation in accuracy benchmarks.

**What remains**: Add `expected_business_impact` field to the ground truth schema and populate it on all new scenarios.

## R5: Ground Truth Schema Extension

**Decision**: Add `expected_business_impact` as an optional list field on `GroundTruthLabel` in `schema.py`. Existing 54 scenarios do not need updating (field is optional). New scenarios should include it.

**Rationale**: The accuracy benchmark can then validate that the mapping function produces the correct business impacts for each scenario's attack category and severity.
