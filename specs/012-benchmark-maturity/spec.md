# Feature Specification: Benchmark Maturity

**Feature Branch**: `012-benchmark-maturity`
**Created**: 2026-04-21
**Last Updated**: 2026-04-22
**Status**: Accepted
**Input**: Close out the v0.13.0 "Benchmark Maturity" milestone by expanding ZIRAN's coverage against published AI agent security benchmarks and adding a structured MITRE ATLAS threat-framework mapping. Covers issues #61, #57, #58, #56, #55, #45, #44, #43, #42.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Align ZIRAN findings with MITRE ATLAS (Priority: P1)

A red team assessor running a ZIRAN campaign against a customer AI agent needs to hand their report to the customer's threat-intelligence team. That team aligns everything to MITRE ATLAS — the recognised taxonomy for adversarial AI threats. Today, ZIRAN reports expose OWASP LLM Top 10 categories but not ATLAS techniques, which forces the assessor to re-classify findings by hand before delivery.

**Why this priority**: ATLAS is the dominant taxonomy for adversarial AI threats, and the 14 agent-specific techniques added in October 2025 align directly with the attacks ZIRAN already executes. Without this mapping, findings are harder to operationalise in customer threat models. This is the flagship outcome of the release.

**Independent Test**: Run any ZIRAN campaign (e.g., against the example LangChain agent) and open the resulting report. Every finding is tagged with one or more ATLAS technique identifiers, and the report contains a coverage summary grouped by ATLAS tactic. Can be validated without any of the other stories in this release landing.

**Acceptance Scenarios**:

1. **Given** a completed campaign, **When** the assessor views the Markdown or HTML report, **Then** each finding displays at least one ATLAS technique identifier and its human-readable name.
2. **Given** the attack library, **When** the assessor filters by a specific ATLAS technique, **Then** they get the list of attack vectors mapped to that technique.
3. **Given** the benchmark dashboard, **When** the assessor reviews it, **Then** the ATLAS coverage row shows a concrete number of techniques mapped and highlights the agent-specific techniques covered.
4. **Given** an attack vector that was previously only OWASP-tagged, **When** the library is re-loaded, **Then** that vector now also carries an ATLAS mapping without its OWASP mapping changing.

---

### User Story 2 - Complete OWASP LLM Top 10 coverage (Priority: P1)

A compliance analyst evaluating ZIRAN for adoption asks "does it cover all ten OWASP LLM categories?". Today the answer is "nine out of ten" — LLM05 (Supply Chain) has only moderate coverage and LLM10 (Model Theft / Unbounded Consumption) is absent. These gaps are visible on the public benchmark dashboard and block a clean compliance story.

**Why this priority**: OWASP is the most common compliance framework asked about by prospective users. The gap is small and well-defined, and closing it turns 90% coverage into 100% — a material change in how ZIRAN reads on comparison sheets.

**Independent Test**: Run the OWASP coverage report generator. All ten categories are reported as "strong" or "comprehensive" (≥10 vectors each), with no "moderate", "planned", or "not covered" entries. Can be validated independently of the ATLAS work.

**Acceptance Scenarios**:

1. **Given** the OWASP coverage dashboard, **When** the analyst reviews LLM05 and LLM10, **Then** both show status "strong" or better with at least 10 vectors each.
2. **Given** the attack library, **When** the analyst runs the library listing filtered by LLM10, **Then** they see concrete vectors covering model extraction, weight approximation, and fine-tuning data extraction.
3. **Given** the same library filtered by LLM05, **When** the analyst reviews results, **Then** they see coverage of malicious plugin detection, dependency compromise, and data pipeline poisoning.

---

### User Story 3 - Demonstrably higher coverage on public benchmarks (Priority: P2)

A prospective user evaluating ZIRAN against competing tools (e.g., Promptfoo, Garak) reads the benchmark comparison table to decide whether the tool justifies adoption. Today ZIRAN shows very low coverage numbers against TensorTrust (<0.1%), WildJailbreak (<0.1%), and partial coverage against ToolEmu and CyberSecEval. Even though full parity is unrealistic for the largest datasets, the current numbers under-represent ZIRAN's actual capabilities because they don't yet reflect unique pattern coverage.

**Why this priority**: This is marketing-adjacent but materially affects adoption decisions. The underlying work also fills real gaps — the current vector library is missing representative patterns from these benchmarks.

**Independent Test**: Regenerate the benchmark comparison table. The TensorTrust, WildJailbreak, ToolEmu, and CyberSecEval rows all show measurably higher coverage or pattern-diversity numbers than before this release.

**Acceptance Scenarios**:

1. **Given** the auto-generated coverage comparison document, **When** a reader views the benchmark comparison table, **Then** the ZIRAN column shows increased vector counts for TensorTrust and WildJailbreak and the progress bar for each is visibly higher.
2. **Given** the ToolEmu coverage row, **When** the reader reviews it, **Then** the sandbox-evasion dimension shows dedicated vectors (not just generic tool-manipulation reuse).
3. **Given** the CyberSecEval row, **When** the reader reviews it, **Then** the row shows specific coverage of code-generation safety and cybersecurity-knowledge dimensions, not just a generic "partial overlap" note.

---

### User Story 4 - Detect retrieval-targeted prompt injection in RAG systems (Priority: P2)

A security engineer whose product uses a retrieval-augmented pipeline (RAG) wants to know whether attackers could plant content that a similarity search would retrieve and the agent would then act on. Today, ZIRAN's indirect-injection vectors assume the injected content is already present in context and don't exercise the retrieval ranking step. The engineer needs attacks that specifically target retrieval.

**Why this priority**: RAG is one of the most common agent architectures in production today, and ZIRAN claims to cover indirect injection. Without retrieval-aware vectors, the coverage story has a visible hole.

**Independent Test**: Select the new RAG poisoning category from the attack library and run those vectors against a test agent. The vectors contain content crafted to rank highly for common queries and are embeddable in multiple document formats.

**Acceptance Scenarios**:

1. **Given** the attack library, **When** the engineer filters by the RAG-poisoning category, **Then** they see vectors specifically designed for retrieval-ranking manipulation.
2. **Given** a RAG-poisoning vector, **When** the engineer reviews its payload, **Then** the content is formatted to appear credible and high-ranking in similarity search (e.g., keyword-dense, credible framing, multiple document-format variants).
3. **Given** these vectors, **When** they are included in a campaign report, **Then** they appear in the OWASP LLM01 category and in the ATLAS indirect-injection mapping alongside existing indirect-injection vectors.

---

### User Story 5 - Measure attacks that bypass active defences (Priority: P3)

A blue team that has already deployed a guardrail system (an input filter, an output guard, or a hybrid) wants to know: of the attacks ZIRAN runs, how many bypass the defences in place? Today, ZIRAN measures success rate against the raw agent but does not report a separate bypass rate against active defences. Without that metric, the team cannot distinguish "the agent is safe" from "the guardrail happened to catch it this time".

**Why this priority**: This is a meaningful capability expansion rather than a coverage fill. It directly addresses the LLMail-Inject / PINT gaps but is more involved than the other work items. It can be scoped as a minimal first version in this release with deeper integrations in a follow-up.

**Independent Test**: Configure a defence profile (declaring what defences are active on the target), run a campaign, and view the resulting report. An evasion rate metric is reported separately from the raw success rate.

**Acceptance Scenarios**:

1. **Given** a campaign configuration, **When** the team declares one or more active defences via a defence profile, **Then** the campaign results include an evasion rate metric alongside the existing success rate.
2. **Given** two campaigns against the same target — one with a defence profile declared, one without — **When** the team compares the reports, **Then** the evasion-rate column only appears on the first report.
3. **Given** the campaign report, **When** a finding is listed, **Then** it indicates whether that specific attack bypassed the declared defences.

---

### Edge Cases

- **Vector without an obvious ATLAS technique.** Some vectors may not map cleanly to any ATLAS technique. The system treats ATLAS mapping as a list (zero or more techniques) so that edge cases can map to "no known technique" rather than forcing a bad fit, but a coverage audit flags any vector with an empty mapping as a follow-up.
- **Deprecated or renamed ATLAS techniques.** ATLAS evolves. If a referenced technique identifier is renamed or deprecated upstream, the coverage report surfaces the discrepancy rather than silently failing.
- **Vector appears in multiple OWASP and multiple ATLAS categories.** Some attacks span categories (e.g., indirect injection used for exfiltration). Both taxonomies accept multi-value mappings and the reports handle multi-tagging without double-counting on coverage totals.
- **Defence profile declared without any defences.** An empty profile is treated the same as no profile — no evasion rate metric is computed; the existing success rate is reported unchanged.
- **Defence profile declares a defence the system doesn't know how to evaluate.** The system accepts the declaration, records it in the report metadata, but marks the evasion rate as "not computable" for that defence rather than silently substituting zero.
- **Generated report consumed by a downstream signing step.** Output remains deterministic (stable key order, stable array order) so that hash-and-sign workflows downstream (e.g., asqav integration in issue #259) remain valid.

## Requirements *(mandatory)*

### Functional Requirements

#### Threat-framework mapping

- **FR-001**: Every attack vector in the library MUST carry a MITRE ATLAS mapping field, independent of its existing OWASP LLM mapping. Both mappings are lists (zero or more entries per vector).
- **FR-002**: The library MUST allow filtering by ATLAS technique identifier, in addition to the existing OWASP filter.
- **FR-003**: Campaign findings MUST expose the ATLAS mapping of the attack that produced them, in both machine-readable (JSON) and human-readable (Markdown / HTML) report formats.
- **FR-004**: The coverage reporting infrastructure MUST produce an ATLAS coverage summary listing the number of techniques mapped, grouped by ATLAS tactic, and highlighting AI-agent-specific techniques.

#### OWASP gap closure

- **FR-005**: The library MUST include at least ten vectors mapped to OWASP LLM05 (Supply Chain Vulnerabilities), spanning malicious tool/plugin detection, compromised dependencies, and data pipeline poisoning.
- **FR-006**: The library MUST include at least ten vectors mapped to OWASP LLM10 (Model Theft / Unbounded Consumption), spanning model extraction, weight approximation, fine-tuning data extraction, and model fingerprinting.
- **FR-007**: The OWASP coverage dashboard MUST report every category as "strong" or "comprehensive" after this release — no category is left at "moderate", "planned", or "not covered".

#### Benchmark coverage expansion

- **FR-008**: The library MUST add representative prompt-injection patterns drawn from TensorTrust, chosen to diversify pattern coverage rather than increase raw count toward full parity.
- **FR-009**: The library MUST add multi-turn jailbreak tactics from WildJailbreak that are not already represented among the existing tactics.
- **FR-010**: The library MUST include dedicated sandbox-evasion vectors that map to ToolEmu's emulated-sandbox evaluation dimension, distinguishable from generic tool-manipulation vectors.
- **FR-011**: The library MUST cover CyberSecEval's code-generation safety and cybersecurity-knowledge dimensions with identifiable vectors rather than relying on generic overlap.

#### RAG poisoning

- **FR-012**: The library MUST include a retrieval-aware indirect-injection category containing vectors whose payloads are crafted for high similarity-search ranking.
- **FR-013**: RAG poisoning vectors MUST include multiple document-format framings (e.g., email, web page, database record) so that realistic retrieval contexts are exercised.
- **FR-014**: Each RAG poisoning vector MUST carry both an OWASP LLM01 mapping and an ATLAS indirect-injection technique mapping.

#### Defence-evasion measurement

- **FR-015**: Campaign configuration MUST accept an optional defence profile declaring which defences (input filters, output guards, hybrid guardrail systems) are active on the target.
- **FR-016**: When a non-empty defence profile is declared, campaign results MUST include an evasion rate metric defined as the proportion of attempted attacks that succeeded despite the declared defences.
- **FR-017**: When no defence profile is declared (or when the declared profile is empty), reports MUST omit the evasion rate rather than reporting a misleading zero.
- **FR-018**: Individual findings MUST indicate whether they bypassed the declared defences, when a defence profile was present.

#### Report and CLI surface

- **FR-019**: The CLI attack-library listing MUST support filtering by ATLAS technique in the same way it currently supports filtering by OWASP category.
- **FR-020**: All generated report artefacts (JSON, Markdown, HTML) MUST produce deterministic output (stable key and array ordering) so that hash-and-sign workflows downstream are not broken.
- **FR-021**: The auto-generated benchmark comparison document MUST reflect the new vector counts and ATLAS technique mapping after regeneration, without manual edits.

### Key Entities

- **ATLAS Technique Mapping**: A typed reference from an attack vector to one or more MITRE ATLAS techniques, carrying a technique identifier and human-readable name. Parallel to the existing OWASP mapping.
- **Defence Profile**: A named declaration, supplied at campaign time, describing which defences are active on the target. Consumed by the evasion-rate calculation. Empty profiles are treated as absent.
- **Evasion Rate**: A campaign-level metric expressing the proportion of attacks that succeeded in the presence of the declared defences. Reported only when a non-empty defence profile is present.
- **Coverage Report**: A structured artefact summarising how many ATLAS techniques, OWASP categories, and benchmark dimensions are represented in the library at a given time. Feeds both machine-readable JSON and the published comparison document.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Every attack vector in the library carries a non-empty ATLAS mapping (validated automatically by a lint/coverage script); at least 60 distinct ATLAS techniques are represented; all 14 October-2025 AI-agent-specific techniques are represented.
- **SC-002**: The OWASP coverage dashboard reports all ten categories at "strong" or "comprehensive"; no category is left at a lower tier.
- **SC-003**: On the auto-generated benchmark comparison table, the TensorTrust, WildJailbreak, ToolEmu, and CyberSecEval rows each show a measurable increase in vector count or pattern-diversity versus the v0.26 baseline.
- **SC-004**: A reader of a ZIRAN report can find, for any given finding, the exact ATLAS techniques and OWASP categories it exercises without leaving the report.
- **SC-005**: An operator who declares a defence profile and runs a campaign sees a separate evasion-rate metric in the report; an operator who declares no profile sees an unchanged report with no misleading evasion number.
- **SC-006**: The benchmark comparison document regenerates cleanly (no manual edits) and matches the library state; running the regeneration twice in a row produces identical output (determinism is preserved for downstream signing).
- **SC-007**: A security engineer evaluating a RAG pipeline can select retrieval-targeted vectors from the library and run them against their agent using only existing CLI commands — no one-off scripts.

## Assumptions

- **ATLAS mapping granularity.** Technique-level mapping is the target for this release. Sub-technique detail is welcome where obvious (e.g., where a vector clearly exercises one specific sub-technique) but is not required for completeness. Later releases can tighten granularity if there's demand.
- **ATLAS as a static snapshot.** The set of ATLAS tactics, techniques, and sub-techniques is embedded in the project at a specific snapshot date (the October 2025 release). ATLAS changes are picked up by later releases, not automatically. This matches how OWASP LLM Top 10 is currently embedded.
- **No full benchmark parity.** TensorTrust (126K vectors) and WildJailbreak (105K) are explicitly not targeted for full parity. The release targets representative diversity across unique pattern families.
- **Defence-evasion scope.** This release ships the configuration schema, the evasion-rate metric, and report surfacing. Real integrations with specific commercial guardrails (NeMo Guardrails, Lakera Guard, and similar) are out of scope and tracked as follow-up work.
- **No detection-pipeline changes.** Detection logic (the detector pipeline that classifies a response as successful attack vs refusal) is not modified by this release. Work is confined to the coverage, mapping, reporting, and configuration layers.
- **No UI changes in scope.** The web UI can display ATLAS and evasion-rate fields in a follow-up release. This release ensures the data is present in the API and generated reports so that UI work can consume it.
- **Backwards compatibility.** Existing consumers of the library YAML format, the campaign result JSON, and the CLI continue to work. New fields are additive; old fields are not renamed or removed.
- **Release packaging.** The release is one version bump. Internally it may land as several focused pull requests (e.g., ATLAS mapping → OWASP gaps → benchmark expansion → RAG poisoning → defence evasion) sequenced so each is independently reviewable, but the user-visible delivery is a single version.

## Dependencies

- ZIRAN v0.26 (v0.8 runtime bridge) is the baseline. No unreleased dependencies.
- Existing benchmark infrastructure (`benchmarks/*.py`, `docs/reference/benchmarks/coverage-comparison.md`) is reused and extended; no rewrite.
- Existing attack library YAML format is extended additively; no migration needed for existing consumers.
