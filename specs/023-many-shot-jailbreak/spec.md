# Feature Specification: Many-Shot Jailbreaking Vector Category

**Feature Branch**: `023-many-shot-jailbreak`  
**Created**: 2026-06-17  
**Status**: Active  
**Input**: User description: "Many-shot jailbreaking attack vector category (issue #276): new YAML vector category with configurable n_shots, shot-template rendering from a harm-specific seed corpus, OWASP LLM01 + ATLAS mappings, short-context skip/warn, and a many-shot coverage tag."

## User Scenarios & Testing *(mandatory)*

ZIRAN's attack library tests agents against a broad set of jailbreak techniques, but has no coverage for **many-shot jailbreaking** — a long-context attack that floods a single prompt with many faux "harmful question → compliant answer" examples to condition the model into complying with a final harmful request. As long-context models proliferate, this is a real gap in ZIRAN's coverage. This feature adds a many-shot jailbreaking vector category so users can test whether their agents are susceptible to it.

### User Story 1 - Test agents against many-shot jailbreaking (Priority: P1)

A security engineer scanning an agent wants ZIRAN to include many-shot jailbreaking attacks — prompts that stack many faux compliant examples before a final harmful ask — so a previously-uncovered jailbreak class is exercised and reported with the right risk taxonomy.

**Why this priority**: This is the core deliverable and the whole point of the issue — without the vectors, nothing else matters. It is independently valuable: even at a fixed shot count it closes the coverage gap.

**Independent Test**: Run a scan whose vector set includes the new category and confirm at least ten many-shot vectors execute against a target, each producing a prompt that stacks many faux example exchanges before a final harmful request, and each tagged with the correct OWASP and ATLAS risk categories.

**Acceptance Scenarios**:

1. **Given** the attack library, **When** it is loaded, **Then** the many-shot jailbreaking category contributes at least 10 vectors spanning multiple harm categories.
2. **Given** a many-shot vector, **When** its prompt is rendered, **Then** the prompt contains the configured number of faux example exchanges followed by a single final harmful request.
3. **Given** any many-shot vector, **When** its taxonomy is inspected, **Then** it carries OWASP LLM01 and the ATLAS techniques for LLM Jailbreak and LLM Prompt Crafting.

---

### User Story 2 - Tune the shot count to probe long-context susceptibility (Priority: P2)

A researcher wants to control how many example shots are stacked (the attack's potency scales with shot count and context length), so they can probe a model's susceptibility curve and confirm the attack actually exercises a long context.

**Why this priority**: Configurable shot count is what makes this a *long-context* attack rather than a one-off prompt; it turns a static vector into a tunable probe. It builds on US1's vectors.

**Independent Test**: Render a many-shot vector at a low and a high shot count and confirm the prompt length scales with the count; confirm a high shot count produces a genuinely large (long-context) prompt and that out-of-range counts are clamped to the documented bounds with a warning.

**Acceptance Scenarios**:

1. **Given** a many-shot vector with no override, **When** it is rendered, **Then** it uses the documented default shot count.
2. **Given** a configured shot count, **When** the vector is rendered, **Then** the number of stacked example exchanges matches the configuration and the prompt length scales accordingly.
3. **Given** a shot count outside the supported range, **When** the vector is rendered, **Then** the system clamps it to the nearest documented bound with a warning rather than producing an unbounded or empty prompt.

---

### User Story 3 - Safe targeting of long-context models + coverage visibility (Priority: P3)

An operator running ZIRAN against a mix of models wants many-shot vectors to behave sensibly against short-context targets (which can't hold a many-shot prompt) — skipping or warning rather than erroring — and wants the new coverage to show up in the benchmark dashboard.

**Why this priority**: Protects against confusing failures on incompatible targets and makes the new coverage discoverable. It is lowest priority because the core value lands in US1/US2.

**Independent Test**: Run a many-shot vector against a target whose context capacity is too small and confirm it is skipped and a warning recorded (the over-capacity prompt is not sent, not errored or silently failed); confirm the coverage dashboard lists the new many-shot tag.

**Acceptance Scenarios**:

1. **Given** a target with insufficient context capacity for the configured shot count, **When** a many-shot vector runs, **Then** it is skipped and a warning with a clear reason is recorded (the prompt is not sent), not errored or silently dropped.
2. **Given** the benchmark coverage report, **When** it is generated, **Then** it surfaces a `many-shot` tag reflecting the new vectors.

---

### Edge Cases

- **Synthetic, non-operational shot content**: the example shots must *look* like harmful exchanges (to reproduce the attack pattern) but MUST NOT contain real, operational harmful instructions — ZIRAN is a testing tool, not a harmful-content generator. The corpus is synthetic/templated; the test measures susceptibility to the *pattern*, not the payload.
- **Shot count of zero / negative / absurdly large**: clamped to the documented bounds (floor 1, max 500) with a warning, never producing an empty "many-shot" prompt or an unbounded one that exhausts memory.
- **Short-context target**: a configured shot count whose rendered prompt exceeds the target's context capacity must skip/warn, not error.
- **Detector compatibility**: a many-shot prompt's final request must still be evaluated by the existing detectors the same way as other jailbreak vectors (the long preamble must not break success/failure detection).
- **New ATLAS technique availability**: the LLM-Jailbreak ATLAS technique must be available in the taxonomy for vectors to reference it (see Assumptions).
- **Reproducibility**: rendering the same vector at the same shot count must be deterministic (a stable prompt), so scans and tests are repeatable.

## Clarifications

### Session 2026-06-17

- Q: How is the shot count (`n_shots`) configured? → A: A per-vector default declared in the vector's YAML (self-contained, reproducible) PLUS an optional scan-time override that applies to all many-shot vectors (so a researcher can sweep the count without editing vector files).
- Q: What happens when a many-shot prompt exceeds the target's context capacity? → A: Skip the vector for that target AND emit a warning with the reason (target context too small for the configured shots) — the over-capacity prompt is not sent, and the skip is recorded/visible, never silent.
- Q: Out-of-range shot count — reject or clamp? → A: Clamp to the supported bounds (floor 1, max 500) and emit a warning; clamping keeps a sweeping scan running and stays deterministic, never producing an empty or unbounded prompt.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The attack library MUST provide a many-shot jailbreaking vector category of at least 10 vectors, spanning multiple harm categories.
- **FR-002**: Each many-shot vector MUST render a prompt that stacks a configurable number of faux "harmful question → compliant answer" example exchanges, followed by a single final harmful request.
- **FR-003**: The number of stacked shots MUST be configurable via a per-vector default in the vector's YAML plus an optional scan-time override that applies to all many-shot vectors. It has a documented default (50), a floor of 1, and a documented supported maximum (500); a value outside the range MUST be clamped to the nearest bound with a warning (never rejected/errored, never producing an empty or unbounded prompt).
- **FR-004**: The shots MUST be generated from a harm-specific synthetic seed corpus at scan time; the corpus MUST NOT contain real operational harmful instructions (synthetic/templated only).
- **FR-005**: Every many-shot vector MUST carry the OWASP LLM01 mapping plus the ATLAS techniques for LLM Jailbreak and LLM Prompt Crafting.
- **FR-006**: Rendering a vector at a given shot count MUST be deterministic and MUST scale prompt length with the shot count (more shots → proportionally longer prompt).
- **FR-007**: When a configured many-shot prompt would exceed a target's context capacity, the vector MUST be skipped for that target AND a warning emitted with a clear reason (target context too small for the configured shots); the over-capacity prompt MUST NOT be sent, and the skip MUST be recorded/visible, never errored or silently dropped.
- **FR-008**: A many-shot vector's final request MUST be evaluated by the existing detection pipeline consistently with other jailbreak vectors (the preamble must not break success/failure detection).
- **FR-009**: The benchmark coverage reporting MUST surface a `many-shot` tag reflecting the new vectors.
- **FR-010**: The new vectors MUST load and validate through the existing attack-library mechanism (no separate, parallel loading path) and MUST be addable/extensible as data, consistent with how attack vectors are normally defined.

### Key Entities *(include if data involved)*

- **Many-shot vector**: an attack vector in the new category — its taxonomy (OWASP/ATLAS/harm category), its final harmful request, and its link to a shot corpus + shot-count configuration.
- **Shot**: a single synthetic "harmful question → compliant answer" example exchange, the unit stacked to build the long context.
- **Shot corpus**: the harm-specific collection of synthetic shots a vector draws from when rendering.
- **Shot-count configuration**: the per-vector / per-scan number of shots to stack, with a default and bounds.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: The many-shot category adds at least 10 vectors across multiple harm categories, each carrying OWASP LLM01 + the two required ATLAS techniques.
- **SC-002**: Rendering a many-shot vector at 100 shots produces a prompt of at least ~50,000 tokens, and prompt length scales with the shot count.
- **SC-003**: The shot count is configurable with a default of 50, a floor of 1, and a supported maximum of 500; values outside the range are clamped to the nearest bound with a warning, never producing an empty or unbounded prompt.
- **SC-004**: Against a target that cannot hold the configured prompt, the vector is skipped and a warning with the reason is recorded (verifiable: the prompt is not sent, no error, no silent drop).
- **SC-005**: The benchmark coverage report shows a `many-shot` tag for the new vectors.
- **SC-006**: Re-rendering the same vector at the same shot count yields an identical prompt (reproducible).

## Assumptions

- **ATLAS technique availability**: the ATLAS technique for "LLM Jailbreak" (AML.T0054) is required by the vectors; if it is not already in ZIRAN's ATLAS taxonomy it will be added as part of this work (LLM Prompt Crafting / AML.T0065 already exists).
- **Shot content is synthetic**: the seed corpus is templated/synthetic faux-harmful exchanges, not real operational harmful instructions — sufficient to reproduce the conditioning pattern while keeping the tool safe. This is a deliberate scope/safety boundary.
- **Token budget for SC-002**: "≈50k tokens at 100 shots" implies each synthetic shot averages on the order of a few hundred tokens; exact corpus sizing is a design detail.
- **Context capacity signal**: the target's usable context capacity is known or configurable (from target/model config) so the skip/warn decision in FR-007 can be made; the precise source is a design detail.
- **Shot count range**: default 50, floor 1, maximum 500; out-of-range values are clamped with a warning (resolved in Clarifications).
- Existing OWASP/ATLAS/harm-category taxonomies and the existing attack-library loader and benchmark coverage tooling are reused.

## Dependencies

- The existing attack vector library and YAML vector schema (`ziran/application/attacks/`, `ziran/domain/entities/attack.py`).
- The OWASP and ATLAS taxonomies used by existing vectors (ATLAS enum may need the LLM-Jailbreak technique added).
- The detection pipeline that evaluates attack success/failure.
- The benchmark coverage / inventory tooling (`benchmarks/`).
- Reference: Anthropic, "Many-shot jailbreaking" (2024).
