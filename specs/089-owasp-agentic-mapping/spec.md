# Feature Specification: map attack vectors to the OWASP Top 10 for Agentic Applications

**Feature Branch**: `feat/089-owasp-agentic-mapping`
**Created**: 2026-11-23
**Status**: Active
**Plan item**: A-OWASP-AGENTIC (goal G-a), issue #536 row 8.
**Base**: `develop` @ 3b0589a.

## The promise in our own words

Today a vector carries OWASP LLM Top 10 ids (`owasp_mapping`) and MITRE ATLAS ids
(`atlas_mapping`). The OWASP Top 10 for Agentic Applications appears only as a prose table in
`docs/concepts/agent-security-landscape.md`, and that table cites `AGT01..AGT10`, which are not
the ids OWASP published.

After this change:

1. `ziran/domain/entities/attack.py` has an `OwaspAgenticCategory` StrEnum `ASI01..ASI10` and an
   `OWASP_AGENTIC_DESCRIPTIONS` dict with the published names (OWASP GenAI Security Project,
   2025-12-09, <https://genai.owasp.org/top-10-for-agentic-applications-2026/>).
2. `AttackVector` and `AttackResult` gain `owasp_agentic_mapping: list[OwaspAgenticCategory]`.
3. The library loader fills the field from one default per `AttackCategory`. A vector YAML may
   set `owasp_agentic_mapping` itself; that value replaces the default. Only vectors whose
   default is wrong set it: supply-chain vectors (ASI04) and code-execution vectors (ASI05).
4. `AttackLibrary.lint_owasp_agentic_coverage()` lists vectors with no Agentic mapping, like
   `lint_atlas_coverage`. A unit test fails when the built-in library has any.
5. Every place that copies `owasp_mapping` from a vector to a result also copies the new field:
   `AttackExecutor`, `TacticExecutor`, `PairExecutor` and the MCP server-surface scorer
   (`score_reply` and the `build_campaign_result` artifacts, which `ziran mcp-hostile-server`
   fills from the library's vectors). The scan JSON carries it, since results are serialized
   with `model_dump`. The dynamic vector generator sets the same category default on the
   vectors it builds.
6. The PoC generator's OWASP lines list the Agentic ids after the LLM ids.
7. The docs table uses `ASI01..ASI10` with the published names.

Out of scope: SARIF properties, new vectors.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Every vector reports its Agentic Top 10 risk (Priority: P1)

A security engineer filters or reports findings by the OWASP Agentic list.

**Acceptance Scenarios**:

1. **Given** the built-in vector library, **When** it loads, **Then** every vector has a
   non-empty `owasp_agentic_mapping` and `lint_owasp_agentic_coverage()` returns `[]`.
2. **Given** a vector YAML with an explicit `owasp_agentic_mapping`, **When** it loads, **Then**
   the explicit value replaces the category default.
3. **Given** a scan, **When** an attack runs (single prompt, multi-turn tactic, PAIR, no prompts,
   skipped many-shot), **Then** its `AttackResult` and the scan JSON carry the vector's
   `owasp_agentic_mapping`.

### User Story 2 - The docs cite the published ids (Priority: P2)

1. **Given** `docs/concepts/agent-security-landscape.md`, **When** read, **Then** the Agentic
   column uses `ASI01..ASI10` with the published names.

### Edge Cases

- A YAML value outside `ASI01..ASI10` fails the vector's load, as an unknown OWASP LLM id does.
- An explicit empty list in YAML falls back to the category default, so no vector is unmapped.
- `attack_executor.py` stays within the 400-line module budget.

## Requirements *(mandatory)*

- **FR-001**: `OwaspAgenticCategory` with ten members and a description for each.
- **FR-002**: `owasp_agentic_mapping` on `AttackVector` and `AttackResult`, default empty.
- **FR-003**: a default per `AttackCategory` (`AGENTIC_DEFAULTS`, one entry for every
  category), applied by `_parse_vector` when YAML sets none and by the dynamic vector generator.
- **FR-004**: `lint_owasp_agentic_coverage()` returns sorted ids with an empty mapping.
- **FR-005**: all result builders that copy `owasp_mapping` copy the new field.
- **FR-006**: the PoC OWASP lines include the Agentic ids.
- **FR-007**: the docs table uses the published ids and names.

## Success Criteria *(mandatory)*

- **SC-001**: the built-in library lint returns `[]` in a unit test.
- **SC-002**: `tests/unit/application/test_scanner_size.py` passes.

## Assumptions

- ASI06 keeps the published ampersand ("Memory & Context Poisoning"); the plan item wrote "and".
  Overturned if OWASP's text changes.
- Category defaults: prompt injection, indirect injection, system prompt extraction and chain of
  thought manipulation map to ASI01 (the attacker redirects the agent's goal or reasoning); tool
  manipulation, data exfiltration and model DoS to ASI02 (misuse of granted tools and resources);
  privilege escalation and authorization bypass to ASI03; memory poisoning to ASI06; multi-agent
  to ASI07. ASI08, ASI09 and ASI10 have no default, since no category tests them directly.
  Overturned by a reviewer who reads a category differently; a YAML override fixes a vector.
- An override for an indirect-injection vector keeps ASI01 beside the specific id, because the
  injection is still the entry point. Other overrides list the specific id alone.
