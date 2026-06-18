# Implementation Plan: Many-Shot Jailbreaking Vector Category

**Branch**: `023-many-shot-jailbreak` | **Date**: 2026-06-17 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/023-many-shot-jailbreak/spec.md`

## Summary

Add a many-shot jailbreaking attack category: ≥10 YAML vectors whose prompts are built at scan time by stacking N synthetic "harmful question → compliant answer" shots before a final harmful request, conditioning long-context models to comply. Shot count is configurable (per-vector default 50, scan-time override, clamped to [1, ≈500]); against a target too small to hold the prompt the vector is skipped with a warning; the new coverage surfaces via a `many-shot` tag.

**Key design decisions (from the code survey + clarifications):**
- **Vector-level config, not a tactic.** Many-shot is single-turn prompt *augmentation*, not a multi-turn sequence — so add an optional `many_shot` sub-config to `AttackVector` (the YAML loader auto-picks up a new optional Pydantic field). Tactics are for conversational sequences; this is one big prompt.
- **`AML.T0054` (LLM Jailbreak) already exists** in the ATLAS enum (line 216) alongside `AML.T0065` — no enum change needed (corrects a spec assumption).
- **Synthetic corpus (safety boundary, FR-004).** Shots come from a committed synthetic faux-harmful corpus keyed by harm category — templated, non-operational; the test exercises the *pattern*, never ships real harmful payloads.
- **Char-heuristic token estimate** (~4 chars/token) for the context-capacity check — deterministic, no new dependency (avoids adding `tiktoken` to the hot path); the same heuristic backs the SC-002 "≥50k tokens at 100 shots" check.
- **Context capacity via scan config** (`context_window`, default large) threaded scanner → executor — the simplest "known or configurable" source (target-config integration is a later refinement).

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary Dependencies**: Pydantic v2 (`ManyShotConfig` model + validators), PyYAML (vectors + synthetic corpus loading), existing `AttackLibrary` / `AttackExecutor` / `AgentScanner`. No new runtime dependencies (token estimate is a char heuristic, not `tiktoken`).
**Storage**: YAML — the vector file (`ziran/application/attacks/vectors/many_shot_jailbreak.yaml`) and a synthetic shot corpus (`ziran/application/attacks/many_shot_corpus.yaml`).
**Testing**: pytest unit + integration markers.
**Target Platform**: Library + CLI.
**Project Type**: Single project, hexagonal layout in place.
**Performance Goals**: Rendering 500 shots is fast (string assembly); the context-capacity check prevents sending oversized prompts.
**Constraints**: Deterministic rendering (SC-006); no real operational harmful content in the corpus (FR-004); no new runtime dependency.
**Scale/Scope**: ≥10 vectors across multiple harm categories; shot count 1..≈500 (default 50); ≈50k tokens at 100 shots.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Assessment |
|-----------|------------|
| **I. Hexagonal Architecture** | ✅ `ManyShotConfig` is a domain entity (Pydantic, with `AttackVector`); the `ShotRenderer` + corpus loader live in the application layer (`ziran/application/attacks/`); the rendering hook is in the application scanner/executor. No infrastructure or new ports needed. |
| **II. Type Safety** | ✅ `ManyShotConfig` is a Pydantic v2 model with field validators (`n_shots` ge=1/le=500); full annotations; mypy strict. |
| **III. Test Coverage** | ✅ Unit: shot rendering determinism, n_shots clamp + override, token estimate, schema validation, corpus safety (no banned operational markers). Integration: a scan runs a many-shot vector end-to-end; 100 shots → ≥50k estimated tokens; short-context target is skipped+warned. Target ≥85%. |
| **IV. Async-First** | ✅ The executor path is async; shot assembly is synchronous CPU work invoked within it (no blocking I/O added). |
| **V. Extensibility via Adapters** | ✅ New vectors are **YAML data** (constitution: "new attack vectors as YAML, not code"). The one code extension — an optional `many_shot` field + a renderer — is the minimal mechanism the data needs, reused by all such vectors. |
| **VI. Simplicity** | ✅ Reuses the existing loader/executor/inventory; char-heuristic token estimate avoids a `tiktoken` dependency; many-shot is a config field, not a new tactic subsystem. |

**Result**: PASS — no violations. Complexity Tracking left empty.

## Project Structure

### Documentation (this feature)

```text
specs/023-many-shot-jailbreak/
├── plan.md         # This file
├── research.md     # Phase 0 output
├── data-model.md   # Phase 1 output
├── quickstart.md   # Phase 1 output
├── contracts/      # Phase 1 output (vector + corpus YAML schema)
└── tasks.md        # Phase 2 (/speckit.tasks — NOT created here)
```

### Source Code (repository root)

```text
ziran/
├── domain/entities/
│   └── attack.py                       # MODIFY: add ManyShotConfig model + AttackVector.many_shot field
├── application/
│   ├── attacks/
│   │   ├── many_shot.py                # NEW: ShotRenderer (load corpus, render N shots deterministically,
│   │   │                               #      clamp n_shots, estimate tokens)
│   │   ├── vectors/
│   │   │   ├── many_shot_jailbreak.yaml # NEW: >=10 vectors (tactic single, many_shot config, OWASP LLM01,
│   │   │   │                            #      ATLAS T0054+T0065, `many-shot` tag, harm categories)
│   │   │   └── many_shot_corpus.yaml    # NEW: synthetic faux-harmful shot corpus, keyed by harm category
│   │   └── library.py                  # (unchanged — new optional field auto-loads)
│   └── agent_scanner/
│       ├── attack_executor.py          # MODIFY: expand many-shot prompt before invoke; skip+warn over capacity;
│       │                               #         accept n_shots override + context_window
│       └── scanner.py                  # MODIFY: thread config n_shots / context_window -> executor

benchmarks/
└── inventory.py                        # MODIFY: expose tag distribution incl. `many-shot` count (FR-009)
                                        # generate_all.py shows it in the coverage report

docs/concepts/
└── attack-vectors.md                   # MODIFY: add a "Long-context attacks" section

tests/
├── unit/                               # renderer determinism/clamp, token estimate, schema, corpus safety
└── integration/                        # scan runs many-shot vector; 100 shots >=50k tokens; short-context skip
```

**Structure Decision**: Single-project hexagonal layout. The behaviour change is a thin, reused mechanism (`ManyShotConfig` + `ShotRenderer` + an executor hook); the bulk is **data** (the vector file + synthetic corpus), consistent with the constitution's "attack vectors are YAML" principle.

## Design Notes (carried into Phase 1)

- **`ManyShotConfig`** (domain): `n_shots: int = 50` (ge=1, le=500), `corpus: str` (harm-category key into the corpus file). `AttackVector.many_shot: ManyShotConfig | None = None`.
- **`ShotRenderer`** (application): loads `many_shot_corpus.yaml` once; `render(corpus_key, n) -> str` deterministically assembles `n` shots by cycling the corpus's shot list (stable order), so the same (key, n) always yields the same text (SC-006). `clamp(n) -> (value, warned)` enforces [1, 500]. `estimate_tokens(text) -> int` via `len(text) // 4`.
- **Executor hook** (`attack_executor.py`, before `adapter.invoke`): if `attack.many_shot`, compute effective n = clamp(override or config default or vector default); build `prompt = shots + "\n\n" + rendered_template`; if `estimate_tokens(prompt) > context_window`, **skip + warn** (record the result as skipped with a clear reason via the emitter / a non-successful `AttackResult`, FR-007), else send. The final request is the existing rendered template, so detectors evaluate it unchanged (FR-008).
- **Config threading**: `AgentScanner` reads `config["n_shots"]` (override, optional) and `config["context_window"]` (default ~200k) and passes them to `AttackExecutor.__init__`.
- **Vectors + corpus**: ≥10 vectors spanning harm categories (cybercrime, fraud, weapons, etc.), each `tactic: single`, `many_shot: {n_shots: 50, corpus: <harm>}`, `owasp_mapping: [LLM01]`, `atlas_mapping: [AML.T0054, AML.T0065]`, `tags: [..., many-shot]`, `harm_category` set. The corpus holds synthetic Q/A shots per harm key — non-operational placeholders (a unit test asserts no banned operational markers).
- **Coverage** (`inventory.py`): expose `tags` distribution (and/or a `many_shot_vectors` list); `generate_all.py` surfaces the `many-shot` tag in the report (FR-009).

## Complexity Tracking

> No constitution violations — section intentionally empty.
