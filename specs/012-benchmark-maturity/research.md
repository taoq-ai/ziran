# Phase 0 Research: Benchmark Maturity

**Feature**: 012-benchmark-maturity
**Date**: 2026-04-21

The spec did not introduce any `[NEEDS CLARIFICATION]` markers — the questions that could have required clarification are resolved in the Assumptions section with informed defaults. This research document records the decisions behind those defaults plus the external-data research needed to execute the plan.

## 1. ATLAS snapshot source & granularity

**Decision**: Pin to the MITRE ATLAS October 2025 release (covers 15 tactics, 66 techniques + 46 sub-techniques, 14 new agent-specific techniques). Embed technique IDs and human-readable names as a `StrEnum` + `dict[Enum, str]` pair inside `ziran/domain/entities/attack.py`, mirroring the existing `OwaspLlmCategory` and `OWASP_LLM_DESCRIPTIONS` pattern.

**Rationale**:
- The OWASP pattern is already understood by the codebase, by downstream consumers (web UI, reports, asqav signing), and by existing tests. Reusing it is cheapest and most predictable.
- ATLAS evolves on a release cadence. A static snapshot pinned to a named release date is easier to reason about than a live fetch, and matches how OWASP is already embedded.
- Technique level is the sweet spot for this release: sub-technique detail is finer than what most downstream consumers can display, and some existing vectors span multiple sub-techniques of the same technique. When a vector clearly targets one sub-technique, we encode that sub-technique as its own enum value alongside the parent — but we don't require it universally.

**Alternatives considered**:
- **Live fetch from the MITRE ATLAS GitHub repo at library-load time.** Rejected: introduces a network dependency on the CLI hot path, violates determinism, and the snapshot approach is already proven for OWASP.
- **Sub-technique-level mapping for every vector.** Rejected: doubles the annotation work for little downstream benefit in this release; can be tightened in a follow-up if UI or compliance workflows need it.
- **Use MITRE ATT&CK for Enterprise instead.** Rejected: ATT&CK is enterprise-system focused; ATLAS is the AI-specific taxonomy the spec targets.

## 2. ATLAS taxonomy data layout

**Decision**: Three module-level constants in `ziran/domain/entities/attack.py`:
- `AtlasTactic` — `StrEnum` listing the 15 ATLAS tactics (values like `"AML.TA0002"`).
- `AtlasTechnique` — `StrEnum` listing every technique ID used by at least one vector in the library (values like `"AML.T0051"`). Not every published ATLAS technique is represented — only those that match something ZIRAN actually tests.
- `ATLAS_TECHNIQUE_DESCRIPTIONS: dict[AtlasTechnique, str]` — human-readable names.
- `ATLAS_TECHNIQUE_TO_TACTIC: dict[AtlasTechnique, AtlasTactic]` — the canonical technique→tactic link used by coverage reports.
- `AGENT_SPECIFIC_TECHNIQUES: frozenset[AtlasTechnique]` — the 14 October-2025 agent-specific techniques, used by the benchmark dashboard to highlight those.

**Rationale**: Pydantic's `StrEnum` is already the idiom used for `OwaspLlmCategory`. A `list[AtlasTechnique]` field round-trips cleanly to YAML (as strings) and to JSON reports. Keeping only referenced techniques in the enum avoids surfacing a long empty list of "techniques we don't touch" on the coverage dashboard — the dashboard uses `ATLAS_TECHNIQUE_TO_TACTIC` for the denominator.

**Alternatives considered**:
- **Enumerate every published ATLAS technique**, even unreferenced ones. Rejected: the dashboard is clearer when it shows only techniques the library actually targets; unreferenced techniques are visible as "gaps" in `ATLAS_TECHNIQUE_TO_TACTIC` vs `AtlasTechnique` if we need that later.
- **String IDs with a separate registry JSON file.** Rejected: breaks the consistency with OWASP and loses mypy-checked enum safety.

## 3. Defence-profile scope for the first release

**Decision**: Ship the schema, the metric field, and the report plumbing. Real evaluators for specific guardrail products (NeMo Guardrails, Lakera Guard, others) are out of scope.

**Rationale**:
- The user-facing value of the first release is the data model and report surface. Downstream consumers (web UI, asqav signing, compliance audits) can proceed knowing the field exists even if it's always "declared but not computable" for now.
- Building evaluators requires integration work per guardrail product, with different authentication, different APIs, and different correctness models. That's multiple releases of work. Shipping an empty `evaluable=False` declaration now and wiring it later via the existing `DefenceDeclaration.evaluable` flag is additive and safe.
- The LLMail-Inject and PINT benchmarks describe the evasion-rate metric shape but do not mandate a specific guardrail-product integration. Either benchmark could be measured against a profile once we have an evaluator.

**Alternatives considered**:
- **Ship with a built-in NeMo Guardrails evaluator.** Rejected: one evaluator without others is awkward ("why NeMo and not Lakera?"), and the integration alone is larger than the rest of this release.
- **Omit defence profile entirely this release.** Rejected: blocks the "evasion rate" story from the milestone without solving it later, and the schema is cheap to land now.

## 4. YAML schema additions and backwards compatibility

**Decision**: The new `atlas_mapping` field on attack vectors is added to the Pydantic model with `default_factory=list`. Existing YAML files without the field continue to load. The field is populated in a second pass (Phase 3 — "ATLAS retro-mapping") so that Phase 1 and Phase 2 can land independently.

**Rationale**:
- Splits risk: domain changes land without any YAML churn; YAML churn lands separately and touches only data.
- Matches how `owasp_mapping` was added historically (single PR per layer).
- The library-lint helper (`lint_atlas_coverage`) is advisory in Phase 2 but becomes a CI gate after Phase 3 so main never regresses.

## 5. Benchmark coverage targets

**Decision**:
- **TensorTrust**: ~25 representative patterns — focus on pattern diversity, not count. Pattern families: system-prompt override, credential extraction, tool-output substitution, fake-rulebook framings, multi-language injection.
- **WildJailbreak**: ~10 new multi-turn tactics beyond the current 11. New tactics: progressive hypothetical escalation, persona rewind, compliance weaponisation, moral inversion, Socratic induction.
- **ToolEmu**: ~15 dedicated sandbox-evasion vectors distinct from generic tool-manipulation. Patterns: filesystem-path tricks, process-spawn requests, network-egress probes, sandbox-fingerprinting.
- **CyberSecEval**: ~20 vectors split between code-generation safety and cybersecurity-knowledge.

**Rationale**:
- Full parity with TensorTrust (126K) and WildJailbreak (105K) is explicitly out of scope (Spec Assumption #3). The numbers above are chosen to materially move the coverage-comparison table and cover each benchmark's pattern families without exploding library size.
- The counts keep total library size under ~650 vectors, preserving library-load performance and report sizes.

**Alternatives considered**:
- **Import benchmark datasets directly.** Rejected: licence complexity (TensorTrust is researcher-distributed), and it would 100× library size for diminishing marginal value.
- **Scripted sampling from the benchmarks at scan time.** Rejected: turns static library into a dynamic one, breaking determinism and making reports irreproducible.

## 6. RAG poisoning category placement

**Decision**: Land as a single new YAML file `rag_poisoning.yaml` under the existing `AttackCategory.INDIRECT_INJECTION` category, distinguished by a `rag-poisoning` tag. Each vector's `prompts[*].template` contains retrieval-optimised content (keyword-dense, credible framing, multiple document-format variants).

**Rationale**:
- Preserves category-count stability (no new `AttackCategory` enum value, which would bump reports and downstream consumers).
- Keeps retrieval-targeted attacks discoverable via both `--category indirect_injection` and `--tag rag-poisoning`.
- The retrieval-ranking step is not exercised within ZIRAN's scan loop today (we can't observe retrieval rankings without instrumenting the RAG pipeline). The vectors are still useful in direct injection tests and in indirect-injection harnesses that load them via existing document-format framings (email, web page, database record).

**Alternatives considered**:
- **Add a new `AttackCategory.RAG_POISONING`.** Rejected: adds a category to every downstream report and library dashboard for a sub-class of indirect injection; tag-based distinction is cheaper and reversible.
- **Build a retrieval-ranking harness that scores payloads against a FAISS/Chroma index.** Rejected: scope creep — this is a detection-pipeline change, and the spec excludes detector changes.

## 7. Report determinism

**Decision**: All new fields on `CampaignResult` use `default=None` and are excluded from JSON output via `model_dump(exclude_none=True)`. Lists are emitted in sorted order where sort order is meaningful (techniques by ID, tactics alphabetical), to ensure run-to-run byte-identity.

**Rationale**:
- Downstream signing workflows (issue #259 asqav signing) hash the JSON output. Any non-deterministic ordering breaks signatures.
- `exclude_none=True` means a campaign run without a defence profile produces JSON that is byte-identical to a pre-release run, keeping existing hashes stable.

**Alternatives considered**:
- **Emit `evasion_rate: null` always.** Rejected: breaks byte-identity with pre-release outputs.
- **Rely on Python dict insertion order.** Rejected: relies on Pydantic version behaviour and on the serialisation library; sorting where meaningful is safer.

## 8. Benchmark-script modifications

**Decision**: Add `benchmarks/atlas_coverage.py` as a parallel script to `owasp_coverage.py` — same CLI flags, same JSON-output pattern, same stdout table style. Register in `generate_all.py`. Extend `benchmark_comparison.py` with an ATLAS row plus bumped counts for TensorTrust, WildJailbreak, ToolEmu, CyberSecEval. Regenerate `docs/reference/benchmarks/coverage-comparison.md` — no manual edits.

**Rationale**:
- Symmetric with OWASP keeps developer cognitive load low.
- Generating the Markdown via a script (not by hand) preserves the determinism story — regeneration should be a no-op if library state is unchanged.

## 9. CLI `--atlas` filter UX

**Decision**: `ziran library --atlas AML.T0051` — `click.Choice` built from `[t.value for t in AtlasTechnique]`, case-sensitive (ATLAS IDs are case-sensitive in the canonical form). Error on invalid ID with a suggestion pulled from the closest-matching known technique (`difflib.get_close_matches`, already stdlib).

**Rationale**:
- Mirrors the existing `--owasp` flag exactly.
- `difflib` is stdlib, no dependency added.

**Alternatives considered**:
- **Free-form string filter with post-hoc validation.** Rejected: loses mypy/click validation and gives worse error messages.
- **Case-insensitive matching.** Rejected: ATLAS IDs are case-sensitive in the canonical form and standardising on the canonical form in the CLI reduces report-comparison friction.

## 10. Test strategy

**Decision**:
- **Unit**: enum completeness (`AtlasTechnique` keys == `ATLAS_TECHNIQUE_DESCRIPTIONS` keys == `ATLAS_TECHNIQUE_TO_TACTIC` keys); agent-specific set has exactly 14 entries; `get_attacks_by_atlas` returns correct subsets; `compute_evasion_rate` handles all four cases (None profile, empty profile, profile with no evaluable defences, profile with evaluable defences); `DefenceProfile` Pydantic validation.
- **Integration**: CLI `--atlas` filter end-to-end; `benchmarks/atlas_coverage.py` JSON-output shape and byte-for-byte determinism on two runs; MD and HTML reports contain ATLAS sections when findings exist; campaign-with-profile includes declared-defences metadata; campaign-without-profile has zero evasion-related fields in JSON.
- **Regression**: existing OWASP coverage script still passes; existing report snapshots still round-trip; library load time unchanged within 10% tolerance (smoke test, not blocking).

**Rationale**: Coverage ≥ 85% on new code is enforced by the constitution. The integration tests mirror the existing CLI and benchmark tests to keep the surface consistent.

## Open items for Phase 1

None. All decisions above are concrete enough to proceed to data-model and contracts.
