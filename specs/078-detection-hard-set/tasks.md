# Tasks: harder detection slices and a library crossfire metric

**Spec**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md)

- [x] T001 Read the item, the spec-021 benchmark, the generator, the schema, the pipeline and the lead's probes
- [x] T002 Reproduce the lead probe on develop `4d26d62` (509 of 138,300 pairs, 101 vectors)
- [x] T003 Write spec.md with the labelling rules
- [x] T004 Write `tests/integration/test_detection_hard_set.py` and run it red (import error)
- [x] T005 Add per-category confusion, `--categories` and `--crossfire` to `detection_accuracy.py`
- [x] T006 Carry crossfire in `detection_regression.py`
- [x] T007 Add the four categories to `DetectionCategory`
- [x] T008 Write the four slices in `generate_dataset.py`, regenerate, confirm the spec-021 files are unchanged
- [x] T009 Run the new test green; restrict the two whole-dataset perfection tests to the spec-021 categories
- [x] T010 Regenerate the baseline with `--update-baseline --crossfire`; record the numbers in spec.md
- [x] T011 Update `docs/reference/benchmarks/detection-accuracy.md`
- [x] T012 Run ruff check, ruff format --check, mypy strict and pytest with coverage
