# Phase 1 Data Model: Many-Shot Jailbreaking Vector Category

All structures are Pydantic v2 (Constitution II). Existing models reused/extended where noted.

## ManyShotConfig (NEW — `ziran/domain/entities/attack.py`)

Per-vector many-shot configuration, carried on `AttackVector`.

| Field | Type | Default | Validation |
|-------|------|---------|------------|
| `n_shots` | `int` | `50` | `ge=1, le=500` — the default number of shots to stack |
| `corpus` | `str` | (required) | harm-category key into the shot corpus (e.g. `cybercrime`) |

Notes: the Pydantic bounds protect YAML authoring (out-of-range default → load error). The *runtime* effective count (override path) is clamped separately by the renderer with a warning (R7).

## AttackVector (MODIFY — `ziran/domain/entities/attack.py`)

Add one optional field; everything else unchanged. The YAML loader builds `AttackVector(**data)`, so the field auto-loads.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `many_shot` | `ManyShotConfig \| None` | `None` | present → the executor expands the prompt with stacked shots before sending |

## Shot corpus (NEW data — `ziran/application/attacks/many_shot_corpus.yaml`)

A mapping of harm-category key → ordered list of synthetic shots.

```text
corpus:
  <harm_key>:
    - q: "<synthetic harmful-style question>"
      a: "<synthetic NON-OPERATIONAL compliant-sounding answer>"
    - ...
```

Constraints: answers are synthetic placeholders — no real operational harmful instructions (FR-004); each harm key has a non-empty ordered list; order is stable (determinism).

## ShotRenderer (NEW behaviour — `ziran/application/attacks/many_shot.py`)

Loads the corpus once and renders shots.

- `render(corpus_key: str, n: int) -> str` — assemble `n` shots from `corpus[key]`, cycling the ordered list (`shots[i % len]`), each formatted consistently (e.g. `Q: …\nA: …`), joined deterministically. Same `(key, n)` → identical text (SC-006). Unknown key → clear error.
- `clamp(n: int) -> tuple[int, bool]` — return `(min(max(n, 1), 500), was_clamped)`.
- `estimate_tokens(text: str) -> int` — `len(text) // 4`.

## Effective shot count (runtime resolution)

```text
requested = scan_override (config["n_shots"]) if set else vector.many_shot.n_shots
effective, warned = ShotRenderer.clamp(requested)
```

## Executor inputs (MODIFY — `AttackExecutor`)

| Input | Type | Default | Source |
|-------|------|---------|--------|
| `n_shots` (override) | `int \| None` | `None` | scanner config `config["n_shots"]` |
| `context_window` | `int` | `200_000` | scanner config `config["context_window"]` |

Behaviour: for a `many_shot` vector, build `prompt = render(corpus, effective) + "\n\n" + rendered_template`; if `estimate_tokens(prompt) > context_window` → skip + warn (record a non-successful/“skipped” `AttackResult` with a clear reason, FR-007); else invoke as normal. The final request (rendered template) is unchanged, so detectors evaluate it exactly as for other jailbreak vectors (FR-008).

## Coverage (MODIFY — `benchmarks/inventory.py`)

| Field added | Type | Notes |
|-------------|------|-------|
| `tags` | `dict[str,int]` | full tag distribution (already counted internally; now exposed) |
| `many_shot_vectors` | `list[str]` | ids of vectors carrying `many_shot` (optional convenience) |

`generate_all.py` renders a `many-shot` entry in `coverage-comparison.md` (FR-009/SC-005).

## Reused (unchanged)

- `AtlasTechnique.LLM_JAILBREAK` (`AML.T0054`) + `LLM_PROMPT_CRAFTING` (`AML.T0065`) — already present.
- `OwaspLlmCategory.LLM01`, `HarmCategory`, `AttackCategory`, `ScanPhase`, `Severity`, `AttackPrompt`.
- `AttackLibrary` loader (`library.py`), `AttackExecutor`/`AgentScanner` execution path.

## Relationships

```text
many_shot_jailbreak.yaml ──load──▶ AttackVector(many_shot=ManyShotConfig)
                                          │
many_shot_corpus.yaml ──▶ ShotRenderer ───┤ (render N shots, clamp, estimate)
                                          ▼
AttackExecutor: prompt = shots + final request ──(fits context_window?)──▶ adapter.invoke
                                          │ no → skip + warn (FR-007)
                                          ▼
                              DetectorPipeline (evaluates final request) ──▶ AttackResult
inventory.py (tags) ──▶ generate_all.py ──▶ coverage-comparison.md (many-shot)
```
