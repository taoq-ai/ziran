# Implementation Plan: indicator tiers for the words that fire on benign replies

**Spec**: [spec.md](spec.md)

## Approach

One word list and one condition in `ziran/application/detectors/indicator.py`. No new
dependency, no vector edit, no change to the pipeline or the benchmark scripts.

1. `_CORROBORATED_INDICATORS`: a frozenset of the 19 domain words, chosen from spec 078's
   crossfire. A scratch probe listed, for each indicator-hit pair, the strong indicators that
   matched; a greedy pass ranked the single words by the pairs they alone carried.
2. `_is_strong_indicator` returns `False` for a corroborated word, as for a generic one.
3. `IndicatorDetector.detect` scores 1.0 when a strong indicator matched or when at least
   `_CORROBORATION_MIN` (2) distinct corroborated words matched; otherwise the existing ambiguous
   result.
4. Two regression tests in `tests/unit/test_detectors.py` (spec 027 FR-006 style) and one new
   assertion in the classification test.
5. Regenerate `benchmarks/results/detection_accuracy_baseline.json` with
   `benchmarks/detection_regression.py --update-baseline --crossfire`; update
   `docs/reference/benchmarks/detection-accuracy.md`.

## Constitution check

- Hexagonal: the change stays in the application-layer detector.
- Type safety: `frozenset[str]` and `int` constants; mypy strict passes.
- Tests: two new unit tests, run red then green; the touched integration tests pass.
- Simplicity: a word list and one condition, the spec-027 mechanism reused.

## Verification

- `benchmarks/detection_accuracy.py --crossfire --by-category` before and after.
- `benchmarks/detection_regression.py` passes against the old baseline before the update.
- `benchmarks/ground_truth/run.py` before and after, outputs compared.
- A library scan: every prompt keeps a strong indicator or two corroborated ones.
- ruff check, ruff format --check, mypy strict locally; full suite and coverage in CI.
