# Phase 0 Research: Many-Shot Jailbreaking Vector Category

All Technical Context unknowns are resolved — the three spec clarifications plus a code survey of the attack library, executor, ATLAS enum, and inventory tooling left no open `NEEDS CLARIFICATION`. Decisions and evidence below.

## R1 — Many-shot as a vector-level config field, not a tactic

- **Decision**: Add an optional `ManyShotConfig` sub-model to `AttackVector` (`many_shot: ManyShotConfig | None`). Vectors stay `tactic: single`; the executor expands the prompt for vectors that carry the config.
- **Rationale**: The `tactic` system (`tactics.py`) models *multi-turn conversational sequences* (crescendo, persona-shift, …) via `TacticExecutor`. Many-shot is single-turn **prompt augmentation** — one large prompt — so a tactic would be a poor fit. The YAML loader (`library.py::_parse_vector`) builds `AttackVector(**data)`, so a new optional Pydantic field auto-loads from YAML with zero loader changes.
- **Alternatives considered**: a `MANY_SHOT` tactic (rejected: misuses the multi-turn machinery, more code); a separate parallel vector type/loader (rejected: violates "no separate loading path", FR-010).

## R2 — ATLAS technique already present

- **Decision**: Use the existing `AtlasTechnique.LLM_JAILBREAK` (`AML.T0054`) and `LLM_PROMPT_CRAFTING` (`AML.T0065`); no enum change.
- **Rationale**: The code survey found `AML.T0054` already in the enum (attack.py:216) with a tactic mapping, contradicting the spec's assumption that it might need adding. Both required techniques exist.
- **Alternatives considered**: adding `AML.T0054` (unnecessary — already there).

## R3 — Synthetic, non-operational shot corpus (safety boundary)

- **Decision**: Ship a committed synthetic corpus (`many_shot_corpus.yaml`) of faux "harmful question → compliant-sounding answer" shots keyed by harm category. The answers are non-operational placeholders that reproduce the *format/conditioning* of many-shot, not real harmful instructions. A unit test asserts the corpus contains no banned operational markers.
- **Rationale**: ZIRAN is a testing tool; many-shot's effect comes substantially from the *pattern* of stacked apparent-compliance. Shipping real operational payloads would make the tool a harmful-content generator — an unacceptable scope (FR-004). Synthetic shots keep it safe while still exercising the attack shape and inflating the context.
- **Alternatives considered**: realistic harmful corpus (rejected: safety); generating shots via an LLM at scan time (rejected: non-deterministic, needs a model, defeats SC-006).

## R4 — Deterministic shot rendering

- **Decision**: `ShotRenderer.render(corpus_key, n)` assembles `n` shots by cycling the corpus's ordered shot list (`shots[i % len(shots)]`) with stable formatting, so the same `(key, n)` always produces identical text (SC-006). Prompt length scales linearly with `n` (SC-002/FR-006).
- **Rationale**: Determinism is required for reproducible scans/tests; cycling a fixed list is the simplest deterministic way to reach an arbitrary `n` from a finite corpus.
- **Alternatives considered**: random sampling (rejected: non-deterministic); requiring the corpus to contain ≥500 distinct shots (rejected: heavy authoring for no benefit — cycling is fine for a conditioning attack).

## R5 — Token estimation without a new dependency

- **Decision**: Estimate tokens as `len(text) // 4` (≈4 chars/token). Use it both for the context-capacity check and for the SC-002 "≥50k tokens at 100 shots" assertion, so corpus sizing and the test agree.
- **Rationale**: `tiktoken` is present in the venv but unused in core code; adding it to the scan hot path is an unjustified dependency for a coarse "does this fit?" check (constitution VI — justify dependencies). The char heuristic is deterministic, dependency-free, and accurate enough to size shots (each synthetic shot is ~a few hundred chars → ~200k+ chars at 100 shots → ≥50k tokens).
- **Alternatives considered**: `tiktoken` exact counting (rejected: new hot-path dependency, model-specific, slower); no estimate / send-and-let-provider-truncate (rejected: FR-007 needs a pre-send capacity decision).

## R6 — Context-capacity source via scan config (clarification Q2 behavior)

- **Decision**: The target's usable context capacity is a scanner config value `context_window` (default a large value, e.g. 200_000), threaded `AgentScanner` → `AttackExecutor`. Before sending a many-shot prompt the executor compares `estimate_tokens(prompt)` to `context_window`; if it exceeds, the vector is **skipped + warned** (recorded, not errored, not silently dropped) per FR-007.
- **Rationale**: `TargetConfig`/`OpenAIConfig` have no `context_window` field today and `BaseAgentAdapter` exposes no capacity method, so the least-invasive "known or configurable" source is scan config. This satisfies FR-007 and is testable (set a small `context_window` → skip+warn). Reading capacity from target/model config is a clean future refinement.
- **Alternatives considered**: per-model context lookup table (rejected: scope creep, staleness); adding a capacity method to every adapter (rejected: broad interface change for one feature).

## R7 — Shot-count configuration + clamping (clarifications Q1, Q3)

- **Decision**: Effective `n_shots` = scan-time override (`config["n_shots"]`, optional) if set, else the vector's `many_shot.n_shots` (YAML default 50). The value is clamped to [1, 500] with a warning when adjusted (never rejected; never empty/unbounded). `ManyShotConfig.n_shots` also carries Pydantic bounds (ge=1, le=500) so authoring errors fail at load.
- **Rationale**: Matches Q1 (per-vector default + scan-time override) and Q3 (clamp + warn). Pydantic bounds protect the YAML; runtime clamp protects the override path so a sweeping scan never hard-fails (Q3 rationale).
- **Alternatives considered**: reject out-of-range (rejected per Q3); scan-time-only or YAML-only config (rejected per Q1).

## R8 — Coverage tag surfacing

- **Decision**: Extend `benchmarks/inventory.py` to expose the tag distribution (and/or a `many_shot_vectors` list); `benchmarks/generate_all.py` renders a `many-shot` line/section in `coverage-comparison.md` (FR-009/SC-005).
- **Rationale**: `inventory.py` already counts `tags` into a `Counter` but only exposes `unique_tags`; exposing the distribution is a small change that makes the new coverage visible, reusing the existing generation pipeline.
- **Alternatives considered**: a bespoke many-shot report (rejected: the coverage doc is the established home).

## Resolved unknowns summary

| Unknown | Resolution |
|---------|-----------|
| Tactic vs config field | Vector-level `many_shot` config (R1) |
| ATLAS T0054 | Already in the enum — no change (R2) |
| Shot content / safety | Synthetic, non-operational corpus + safety test (R3) |
| Deterministic rendering | Cycle the ordered corpus list (R4) |
| Token estimation | `len//4` char heuristic, no new dep (R5) |
| Context-capacity source | Scanner config `context_window`, skip+warn (R6) |
| n_shots config + clamp | Override > vector default; clamp [1,500] + warn (R7) |
| Coverage tag | Expose tag distribution in inventory + report (R8) |
