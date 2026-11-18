# Implementation Plan: harder detection slices and a library crossfire metric

**Spec**: [spec.md](spec.md)

## Approach

Data in the existing `DetectionExample` schema, written by rule in the existing generator, and
two small additions to the benchmark scripts. No new dependency, no file under `ziran/`.

1. `benchmarks/ground_truth/schema.py`: `DetectionCategory` gains `indicator_near_miss`,
   `sensitive_tool_output`, `paraphrased_refusal` and `multilingual`.
2. `benchmarks/ground_truth/detection/generate_dataset.py`: a `HARD_VECTORS` table holds the
   indicator lists (copied from 12 library vectors in `expanded_tactics.yaml`, `a2a_attacks.yaml`,
   `authorization.yaml`, `indirect_injection.yaml`, `data_exfiltration.yaml`,
   `prompt_injection.yaml` and `tool_manipulation.yaml`, plus two `nm_` sets written from the
   crossfire's top words). Four lists hold `(vector, kind, text, justification, tools)` items;
   `_hard_detectors` derives the per-detector labels from the spec rules and `gen_hard` writes
   the YAML. `main()` now deletes only generated ids (`det_<category>_NNN.yaml`), so the two
   hand-written `det_borderline_capability_*` fixtures survive a rerun, and regenerating
   leaves the 228 spec-021 files byte identical (`git status` clean after a run).
3. `benchmarks/detection_accuracy.py`:
   - `ORIGINAL_CATEGORIES`, `HARD_CATEGORIES`, `CATEGORIES = ORIGINAL + HARD`;
   - `load_examples` and `run_benchmark` take `categories`; the CLI takes `--categories`;
   - `DetectorAccuracyResult.per_category_confusion` (category -> pipeline and detector
     confusion), printed by `--by-category`;
   - `CrossfireResult` and `_crossfire`: the lead probe's method (every prompt of every library
     vector, default `DetectorConfig`, vector passed, prompt template as the prompt) over the
     loaded benign replies; `run_benchmark(crossfire=True)` and `--crossfire` add it.
4. `benchmarks/detection_regression.py`: `DetectionAccuracyBaseline.crossfire` (optional, so old
   baselines load), filled by `--update-baseline --crossfire`, printed beside a `--crossfire`
   gate run, never gated. Three small hunks; they touch the same class and `main` as
   G4-PR-DELTA (spec 077), so whichever merges second resolves a short textual conflict and
   regenerates the baseline.
5. `benchmarks/results/detection_accuracy_baseline.json` regenerated with
   `--update-baseline --crossfire`; `docs/reference/benchmarks/detection-accuracy.md` gets the
   slice and crossfire sections.

## Constitution check

- Hexagonal: benchmarks only; no layer touched.
- Type safety: new result fields are Pydantic models; mypy strict on `ziran/` unchanged.
- Tests: `tests/integration/test_detection_hard_set.py` covers the slice floors and labels, the
  held-out-benchmark text search, the pinned spec-021 numbers, per-category sums, crossfire
  counts on a one-reply dataset, crossfire opt-in, and the baseline carrying crossfire. Two tests
  that asserted the whole dataset scores perfectly now restrict to the spec-021 categories.
- Simplicity: no new helper module; the slices reuse `_write` and `_src`.

## Verification

- `uv run python benchmarks/detection_accuracy.py --by-category --crossfire` (numbers in the
  spec's Baseline section).
- `uv run python benchmarks/detection_accuracy.py --crossfire --categories
  clear_refusal,partial_compliance,full_compliance,borderline`: 509 of 139,500, 101 vectors (677 vectors after #505).
- `uv run python benchmarks/detection_regression.py`: exit 0 against the committed baseline.
- `uv run python benchmarks/ground_truth/validate.py`: passes.
