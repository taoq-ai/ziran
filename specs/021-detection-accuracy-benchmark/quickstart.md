# Quickstart: Detector Accuracy Benchmark and Threshold Tuning

## Run the benchmark

```bash
# Score the full labelled dataset with default (shipped) thresholds
uv run python benchmarks/detection_accuracy.py

# Per-category breakdown, markdown output
uv run python benchmarks/detection_accuracy.py --by-category --format markdown

# Apply operator-tuned thresholds
uv run python benchmarks/detection_accuracy.py --config .ziran/detectors.yaml
```

Expected: precision / recall / F1 (+ 95% CI) and a confusion matrix for each of `refusal`, `indicator`, `side_effect`, `llm_judge`, plus the overall pipeline; and a coverage line confirming ≥50 examples per category.

## Check / update the regression baseline

```bash
# Compare current accuracy against the recorded baseline (CI uses this)
uv run python benchmarks/detection_regression.py

# Deliberately re-record the baseline after a justified change
uv run python benchmarks/detection_regression.py --update-baseline
```

Gate: fails if pipeline F1 drops more than 0.02 below baseline. Per-detector deltas are shown but never block.

## Tune thresholds without touching code

Create `.ziran/detectors.yaml` (all keys optional):

```yaml
hit: 0.65          # more sensitive — more recall, less precision
safe: 0.3
side_effect_confidence: 0.8
```

Re-run a detection or the benchmark and observe the verdict/metric shift. Remove the file to return to documented defaults.

## Acceptance walkthrough (maps to spec Success Criteria)

1. **SC-001 / SC-002** — `detection_accuracy.py` prints P/R/F1 for all four detectors + pipeline over ≥200 examples, ≥50/category.
2. **SC-003** — edit a threshold in `.ziran/detectors.yaml`, re-run a detection, see the verdict change; delete the file, behaviour returns to defaults.
3. **SC-004** — make a detector deliberately worse on a branch → `detection_regression.py` exits non-zero; revert → exits zero.
4. **SC-005** — `docs/reference/benchmarks/detection-accuracy.md` explains each default threshold and its revisit conditions.
5. **SC-006** — run the benchmark twice; identical metrics (judge verdicts are replayed from fixtures, no live calls).

## Quality gates (must pass before PR)

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy ziran/
uv run pytest --cov=ziran        # all pass, coverage >= 85%
```

## Where things live

| Concern | Path |
|---------|------|
| Threshold model | `ziran/application/detectors/thresholds.py` |
| Config loader | `ziran/infrastructure/config/detectors.py` |
| Harness | `benchmarks/detection_accuracy.py` |
| Regression gate | `benchmarks/detection_regression.py` |
| Judge replay | `benchmarks/replay_llm_client.py` |
| Dataset | `benchmarks/ground_truth/detection/<category>/*.yaml` |
| Methodology + baseline docs | `docs/reference/benchmarks/detection-accuracy.md` |
