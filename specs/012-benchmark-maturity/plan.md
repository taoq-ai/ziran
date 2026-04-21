# Implementation Plan: Benchmark Maturity

**Branch**: `012-benchmark-maturity` | **Date**: 2026-04-21 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/012-benchmark-maturity/spec.md`

## Summary

Close out the v0.13.0 "Benchmark Maturity" milestone by (a) adding MITRE ATLAS as a second threat-framework mapping alongside OWASP, (b) closing OWASP LLM05 and LLM10 coverage gaps, (c) expanding representative coverage of TensorTrust, WildJailbreak, ToolEmu, and CyberSecEval, (d) adding a retrieval-aware RAG-poisoning attack category, and (e) introducing a defence-profile configuration and evasion-rate metric. The work mirrors the existing `OwaspLlmCategory` pattern for ATLAS, adds attack vectors purely as YAML data, and extends the existing benchmark scripts under `benchmarks/`. No new runtime dependencies; no detection-pipeline changes.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix: 3.11, 3.12, 3.13)
**Primary Dependencies**: pydantic (models), PyYAML (vector loader), click (CLI), rich (reports), networkx (graph — unchanged). No new dependencies.
**Storage**: YAML vector files under `ziran/application/attacks/vectors/`; benchmark result JSON under `benchmarks/results/`; docs under `docs/reference/benchmarks/`.
**Testing**: pytest with `@pytest.mark.unit` and `@pytest.mark.integration`; existing fixtures for library and reports.
**Target Platform**: Linux/macOS CLI; Python library.
**Project Type**: CLI tool + Python library (single project, hexagonal architecture).
**Performance Goals**: Library load ≤ 2s with ~600 vectors; ATLAS coverage script ≤ 5s; benchmark comparison regeneration ≤ 10s.
**Constraints**: Deterministic report output (stable key/array order); backwards-compatible additions to attack vector YAML schema; no changes to detector pipeline or adapter interfaces.
**Scale/Scope**: ~565 existing vectors to retro-map; target ~650 vectors post-release; ~60+ ATLAS techniques; all 14 October-2025 AI-agent-specific ATLAS techniques covered.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Hexagonal Architecture | ✅ Pass | `AtlasTactic` / `AtlasTechnique` enums and `atlas_mapping` field live in `domain/entities/attack.py` alongside existing `OwaspLlmCategory`. `DefenceProfile` entity lives in domain. `EvasionMetric` computation is an application-layer pure function. No new ports or adapters (ATLAS is an embedded taxonomy, not an external system). Benchmark scripts live under `benchmarks/` as tooling (outside `ziran/`). |
| II. Type Safety | ✅ Pass | All new models are Pydantic; all enums are `StrEnum`; all functions typed; mypy strict. |
| III. Test Coverage | ✅ Pass | Unit tests: ATLAS enum completeness, `get_attacks_by_atlas`, `atlas_mapping` non-empty lint, evasion-rate computation, defence-profile validation, RAG poisoning YAML load. Integration tests: CLI `--atlas` filter, `benchmarks/atlas_coverage.py` JSON output, report ATLAS sections, campaign with and without defence profile. Target ≥ 85%. |
| IV. Async-First | ✅ Pass | No new I/O introduced. Defence-profile consumption and evasion-rate computation are pure functions on campaign data already in memory. |
| V. Extensibility via Adapters | ✅ Pass | All new attack vectors added as YAML under `ziran/application/attacks/vectors/`, not as code. No new adapter interfaces are modified. |
| VI. Simplicity | ✅ Pass | ATLAS mapping mirrors the existing OWASP pattern exactly — same list-of-enum field shape, same library-filter signature, same report-surface approach. Defence profile is a thin Pydantic model; evasion rate is one function. No new abstractions. |

No violations. No complexity justifications needed.

## Project Structure

### Documentation (this feature)

```text
specs/012-benchmark-maturity/
├── spec.md
├── plan.md                # This file
├── research.md            # Phase 0 output
├── data-model.md          # Phase 1 output
├── quickstart.md          # Phase 1 output
├── contracts/             # Phase 1 output
│   ├── attack-vector-yaml.md     # YAML schema additions
│   ├── atlas-taxonomy.md         # Enum and mapping contracts
│   ├── defence-profile-yaml.md   # Campaign-config schema additions
│   ├── cli-library-atlas.md      # CLI --atlas flag contract
│   └── benchmark-reports.md      # atlas_coverage.py JSON schema
├── checklists/
│   └── requirements.md    # Quality checklist (already written)
└── tasks.md               # Phase 2 output (/speckit.tasks — NOT created here)
```

### Source Code (repository root)

```text
ziran/
├── domain/
│   └── entities/
│       ├── attack.py                   # MODIFIED: AtlasTactic, AtlasTechnique, ATLAS_TECHNIQUE_DESCRIPTIONS,
│       │                                # atlas_mapping field on AttackVector and AttackResult.
│       └── campaign.py                 # MODIFIED: DefenceProfile, EvasionMetric; CampaignResult gains
│                                       # optional evasion_rate and defence_profile fields.
├── application/
│   ├── attacks/
│   │   ├── library.py                  # MODIFIED: get_attacks_by_atlas(), lint helper that reports
│   │   │                               # vectors without atlas_mapping.
│   │   └── vectors/
│   │       ├── *.yaml                  # MODIFIED: every existing YAML file gains atlas_mapping entries
│   │       │                           # on each vector (retro-mapping).
│   │       ├── supply_chain.yaml           # NEW: ≥10 LLM05 vectors.
│   │       ├── model_theft.yaml            # NEW: ≥10 LLM10 vectors.
│   │       ├── tensortrust_patterns.yaml   # NEW: representative patterns.
│   │       ├── wildjailbreak_tactics.yaml  # NEW: new multi-turn tactics.
│   │       ├── toolemu_sandbox.yaml        # NEW: sandbox-evasion vectors.
│   │       ├── cyberseceval_codegen.yaml   # NEW: code-gen safety + cybersec knowledge.
│   │       └── rag_poisoning.yaml          # NEW: retrieval-targeted indirect injection.
│   └── campaign/
│       └── evasion.py                  # NEW: compute_evasion_rate(findings, defence_profile) → float | None.
├── interfaces/
│   └── cli/
│       ├── main.py                     # MODIFIED: add --atlas filter, add --defence-profile config flag
│       │                               # on scan subcommand.
│       └── reports.py                  # MODIFIED: MD/HTML templates gain ATLAS sections and
│                                       # conditional evasion-rate row.
└── infrastructure/
    └── reports/                        # (existing) templates extended; no new files.

benchmarks/
├── atlas_coverage.py                   # NEW: generate ATLAS technique coverage JSON report.
├── benchmark_comparison.py             # MODIFIED: add ATLAS row, bump TensorTrust/WildJailbreak/
│                                       # ToolEmu/CyberSecEval counts, and include RAG benchmark row.
├── owasp_coverage.py                   # MODIFIED: LLM05 threshold check, LLM10 row added; planned-issues
│                                       # map trimmed.
├── generate_all.py                     # MODIFIED: invoke atlas_coverage.py alongside others.
├── inventory.py                        # MODIFIED: include atlas_mapping coverage in inventory.
└── results/                            # (existing) generated artefacts — atlas_coverage.json new.

docs/
└── reference/
    └── benchmarks/
        ├── coverage-comparison.md      # MODIFIED: regenerated with ATLAS section + bumped benchmark rows.
        └── atlas-mapping.md            # NEW: how ATLAS mapping is structured, snapshot date, links to ATLAS.

tests/
├── unit/
│   ├── test_atlas_enum.py              # NEW: enum completeness, description coverage, agent-specific list.
│   ├── test_library_atlas_filter.py    # NEW: get_attacks_by_atlas + lint helper.
│   ├── test_evasion_metric.py          # NEW: compute_evasion_rate edge cases.
│   ├── test_defence_profile.py         # NEW: Pydantic validation, empty-profile handling.
│   └── test_owasp_coverage.py          # EXTENDED: LLM05/LLM10 thresholds; existing file.
└── integration/
    ├── test_cli_atlas_filter.py        # NEW: `ziran library --atlas AML.T0051` end-to-end.
    ├── test_atlas_coverage_script.py   # NEW: benchmarks/atlas_coverage.py JSON output shape.
    ├── test_report_atlas_section.py    # NEW: MD/HTML reports contain ATLAS tables.
    ├── test_campaign_with_defence.py   # NEW: campaign with declared profile yields evasion_rate.
    └── test_campaign_without_defence.py # NEW: campaign with no profile has no evasion_rate field.
```

**Structure Decision**: Single-project hexagonal layout (unchanged). All new code extends the established `ziran/` package across the four layers. No new top-level packages. Attack vectors remain YAML-first. ATLAS taxonomy is embedded in domain, mirroring the existing OWASP pattern.

## Architecture

### A. ATLAS threat-framework mapping

```
domain/entities/attack.py
    AtlasTactic (StrEnum, ~15 values: AML.TA0002 … AML.TA0043)
    AtlasTechnique (StrEnum, enumerates technique IDs used in the library)
    ATLAS_TECHNIQUE_DESCRIPTIONS: dict[AtlasTechnique, str]
    ATLAS_TECHNIQUE_TO_TACTIC: dict[AtlasTechnique, AtlasTactic]
    AGENT_SPECIFIC_TECHNIQUES: frozenset[AtlasTechnique]   # the Oct-2025 14

    AttackVector:
        atlas_mapping: list[AtlasTechnique] = Field(default_factory=list, ...)

    AttackResult:
        atlas_mapping: list[AtlasTechnique] = Field(default_factory=list, ...)

application/attacks/library.py
    def get_attacks_by_atlas(technique: AtlasTechnique) -> list[AttackVector]
    def lint_atlas_coverage() -> list[str]   # returns vector IDs with empty atlas_mapping
```

**Key Design Decisions**:
- **Static snapshot** of ATLAS pinned to the October 2025 release. Matches how OWASP is already embedded. No runtime fetch.
- **Technique-level** granularity. Sub-technique optional and encoded as separate enum values only when a vector clearly targets one specific sub-technique.
- **AGENT_SPECIFIC_TECHNIQUES** is a frozenset for fast membership checks in reports and dashboards.
- Backwards compatibility: `atlas_mapping` defaults to empty list, so existing campaign-result JSON round-trips unchanged. The lint helper is advisory — the library still loads vectors with empty mappings, but the coverage script fails the gate if any vector remains empty in `main`.

### B. OWASP gap closure (LLM05, LLM10)

Pure YAML additions. No code changes other than extending existing unit tests to assert the new vector counts.

- `supply_chain.yaml` (≥10 vectors): malicious plugin manifests; typosquatted tool names piggybacking on known tools; compromised dependency simulation (fake `pip install` payloads surfaced as tool descriptions); data pipeline poisoning via RAG connectors; fine-tuning-data exfiltration prompts.
- `model_theft.yaml` (≥10 vectors): systematic API querying for model extraction; weight approximation probes (temperature-0 deterministic queries); fine-tuning-data extraction (memorisation probes); model fingerprinting (version / RLHF-marker queries); fine-tuning inversion prompts.

Each file uses the established YAML structure: `id`, `name`, `category`, `target_phase`, `description`, `severity`, `prompts`, `tags`, `references`, `owasp_mapping`, and (new in this release) `atlas_mapping`.

### C. Benchmark expansion (TensorTrust, WildJailbreak, ToolEmu, CyberSecEval)

All four are YAML additions. Goal is diversity across unique pattern families, not parity.

- `tensortrust_patterns.yaml` (target ~25 vectors): representative families — explicit system-prompt override, credential-extraction framings, tool-output-substitution, fake-rulebook framings, multi-language injection.
- `wildjailbreak_tactics.yaml` (target ~10 new tactics): tactics not already in `multi_turn_tactics.yaml`. Candidates: progressive hypothetical escalation, persona-rewind, compliance-weaponisation, moral-inversion, Socratic-induction. Each tactic gets at least one representative vector.
- `toolemu_sandbox.yaml` (target ~15 vectors): sandbox-escape probes distinct from the existing tool_manipulation vectors — filesystem-path tricks, process-spawn requests, network egress probes, sandbox-fingerprinting (detect if in emulator and behave benignly vs aggressively).
- `cyberseceval_codegen.yaml` (target ~20 vectors): code-generation safety (unsafe code requests, insecure-pattern solicitation) and cybersecurity knowledge (CVE discussion prompts, exploit-detail elicitation).

### D. RAG-specific poisoning

New `rag_poisoning.yaml` (target ~12 vectors) in the existing `AttackCategory.INDIRECT_INJECTION` family, with a distinguishing tag `tag: rag-poisoning`.

Each vector's `prompts[*].template` contains content designed to rank highly in similarity search: keyword-dense phrasing, trust markers, and variants framed as email, web page, and database record. The prompt renderer doesn't need to change — RAG exercise mode is a test-harness concern; the vectors themselves are already usable via existing indirect-injection flows.

### E. Defence-profile and evasion-rate

```
domain/entities/campaign.py (MODIFIED)
    DefenceProfile:
        name: str
        defences: list[DefenceDeclaration]

    DefenceDeclaration:
        kind: Literal["input_filter", "output_guard", "hybrid"]
        identifier: str           # free-form, e.g., "nemo-guardrails@v0.8" or "custom-regex"
        evaluable: bool = False   # True if ZIRAN knows how to evaluate this defence;
                                  # for now always False — integration work is follow-up.

    CampaignResult: (existing, EXTENDED)
        defence_profile: DefenceProfile | None = None
        evasion_rate: float | None = None   # omitted entirely when None via model_dump(exclude_none=True)

application/campaign/evasion.py (NEW)
    def compute_evasion_rate(
        findings: Sequence[AttackResult],
        profile: DefenceProfile,
    ) -> float | None:
        # If profile is None or has no declared defences → return None.
        # If no declared defence is evaluable → return None (report marks "not computable").
        # Otherwise: proportion of successful attacks that ALSO bypassed evaluable defences.
        # First release has no evaluable defences, so evasion_rate will default to None and reports
        # surface "declared but not computable" metadata. Wire-up is in place for future integrations.
```

**Key Design Decisions**:
- Keep the first-release bar low: declare-only profile, metadata carried through, metric omitted rather than faked. This unblocks downstream report consumers (UI, asqav signing) without committing to specific guardrail integrations.
- `evasion_rate` is `float | None` — when None, `exclude_none=True` on `model_dump` prevents it from appearing in JSON output at all. Deterministic-output requirement (FR-020) preserved.
- Individual `AttackResult` does not need a new bypass-flag field for this release; the per-finding bypass indication is derived from the defence profile and the finding's success state via an application-layer helper. When evaluable defences exist (future release), per-finding flags can be populated by that logic without schema change.

### F. CLI and report surface

- **CLI library filter**: `ziran library --atlas AML.T0051` — mirrors `--owasp LLM01`. Implementation: `click.Choice([t.value for t in AtlasTechnique])` or a free-form validator that checks membership in the enum with a helpful error listing the top candidates.
- **CLI scan defence-profile**: `ziran scan --defence-profile path/to/profile.yaml` — YAML loaded via Pydantic's `DefenceProfile`. Existing scan config schema gains an optional `defence_profile` key so users can keep it in their main config instead of a separate flag.
- **Markdown report**: an "ATLAS Coverage" section listing tactics and the count of findings per tactic, with agent-specific techniques called out. Conditional "Evasion" row appears only when `evasion_rate` is not None or a profile was declared.
- **HTML report**: identical structure to MD; existing template system supports conditional sections.
- **JSON report**: fields added natively via Pydantic `model_dump` — no template changes.

### G. Benchmark scripts

- `benchmarks/atlas_coverage.py` — new script. Walks the attack library, groups by `AtlasTactic`, counts unique techniques represented, asserts all 14 agent-specific techniques are present. Emits JSON to `benchmarks/results/atlas_coverage.json` and a Markdown table to stdout (matching the style of `owasp_coverage.py`).
- `benchmarks/benchmark_comparison.py` — update the target rows for TensorTrust, WildJailbreak, ToolEmu, CyberSecEval to reflect the new vector counts. Add an ATLAS row summarising technique coverage.
- `benchmarks/owasp_coverage.py` — remove `_PLANNED_ISSUES` entries for LLM05 and LLM10 once coverage is achieved. Assert `_STRONG` floor across all categories.
- `benchmarks/generate_all.py` — register `atlas_coverage.py` in the regeneration list.
- `docs/reference/benchmarks/coverage-comparison.md` — regenerate; no manual edits.

## Implementation Phases

Mapped to user stories so each phase is independently reviewable and shippable.

### Phase 1: Domain Foundation

- Add `AtlasTactic`, `AtlasTechnique`, `ATLAS_TECHNIQUE_DESCRIPTIONS`, `ATLAS_TECHNIQUE_TO_TACTIC`, `AGENT_SPECIFIC_TECHNIQUES` to `ziran/domain/entities/attack.py`.
- Add `atlas_mapping: list[AtlasTechnique]` to `AttackVector` and `AttackResult` (default empty).
- Add `DefenceProfile` / `DefenceDeclaration` to domain (`campaign.py` or a new small module if it grows).
- Extend `CampaignResult` with optional `defence_profile` and `evasion_rate` fields, using `exclude_none=True` semantics in serialisation.
- **Gate**: mypy passes; existing tests unchanged pass (backwards compatibility).

### Phase 2: Library + Lint

- Add `AttackLibrary.get_attacks_by_atlas(technique)` and `lint_atlas_coverage()` helper.
- Add compute helper `ziran/application/campaign/evasion.py::compute_evasion_rate`.
- Unit tests for both helpers and enum completeness.
- **Gate**: `ziran library --atlas <value>` works against whatever vectors are already annotated (empty list acceptable at this phase).

### Phase 3: ATLAS retro-mapping (US1 / #61)

- Annotate every YAML file under `ziran/application/attacks/vectors/` with `atlas_mapping` per vector.
- Update `benchmarks/atlas_coverage.py` (new script) to iterate library and produce the JSON + MD output.
- Update `benchmarks/benchmark_comparison.py` to include the ATLAS row.
- Regenerate `docs/reference/benchmarks/coverage-comparison.md`.
- **Gate**: `lint_atlas_coverage()` returns empty list; `atlas_coverage.py` shows ≥ 60 techniques; all 14 agent-specific techniques are present.

### Phase 4: OWASP gap closure (US2 / #42, #43)

- Create `supply_chain.yaml` (≥10 LLM05 vectors) and `model_theft.yaml` (≥10 LLM10 vectors).
- Each new vector carries both `owasp_mapping` and `atlas_mapping`.
- Update existing `owasp_coverage.py` to assert `_STRONG` floor; remove the planned-issues mapping for LLM05/LLM10.
- Regenerate coverage dashboards.
- **Gate**: OWASP coverage script emits `_STRONG` or `_COMPREHENSIVE` for every category.

### Phase 5: Benchmark expansion (US3 / #55, #56, #58, #57)

- Create the four new YAML files (TensorTrust, WildJailbreak, ToolEmu, CyberSecEval).
- Bump corresponding rows in `benchmark_comparison.py`.
- Regenerate coverage-comparison.md.
- **Gate**: benchmark comparison table shows increased vector counts on all four rows.

### Phase 6: RAG-specific poisoning (US4 / #44)

- Create `rag_poisoning.yaml` with ~12 vectors across multiple document framings.
- Each vector uses `category: indirect_injection` and `tag: rag-poisoning`.
- Add integration test that the tag-filter surfaces these vectors and that each carries an ATLAS indirect-injection technique.
- **Gate**: `ziran library --tag rag-poisoning` returns the new vectors; all carry correct OWASP LLM01 + ATLAS mappings.

### Phase 7: Defence profile + evasion rate (US5 / #45)

- Wire `DefenceProfile` into scan config schema (`--defence-profile path.yaml` and a top-level `defence_profile:` key).
- Wire `compute_evasion_rate` into the campaign finalisation step.
- Extend MD/HTML report templates with conditional evasion-rate row and "declared defences" metadata section.
- Unit + integration tests for both "profile present" and "no profile" paths.
- **Gate**: running a campaign with a sample profile produces a report containing the declared defences; without a profile the report has no evasion fields at all.

### Phase 8: CLI + Report surface

- Add `--atlas` filter to `ziran library`.
- Add ATLAS sections to MD/HTML report templates.
- Add `--atlas` column to library listing output (like the existing OWASP column).
- Integration tests for CLI and report content.
- **Gate**: CLI filter and report surfacing work end-to-end.

### Phase 9: Release readiness

- All quality gates: `ruff check .`, `ruff format --check .`, `mypy ziran/`, `pytest --cov=ziran` (≥ 85%).
- Release notes entry noting: ATLAS mapping available, OWASP coverage 10/10, benchmark coverage bumps, new RAG poisoning category, defence-profile schema (guardrail integrations follow-up).
- Validate deterministic output (run report generation twice; diff should be empty).
- **Gate**: CI green on the final PR.

## Packaging / PR strategy

Internally land as 5 focused PRs under the same branch family, each independently reviewable:
1. **Foundation** — Phases 1+2 (enum, entities, helpers, library filter, ATLAS retro-mapping seed).
2. **ATLAS retro-map** — Phase 3 (the large YAML annotation pass + new benchmark script).
3. **OWASP + benchmark expansion** — Phases 4+5+6 (new YAML files for LLM05, LLM10, TensorTrust, WildJailbreak, ToolEmu, CyberSecEval, RAG).
4. **Defence profile + evasion metric** — Phase 7.
5. **Surface + release** — Phases 8+9 (CLI filter, report sections, regenerate dashboards, release notes).

Each PR closes the issues it fully addresses; the final PR closes the milestone. release-please handles the version bump at the end.

## Complexity Tracking

No constitution violations. No complexity justifications needed.
