# Tasks: indicator tiers for the words that fire on benign replies

**Spec**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md)

- [x] T001 Read the item, spec 027, spec 078, the indicator detector, the pipeline and the benchmark scripts
- [x] T002 Run `detection_accuracy.py --crossfire` on 7e0524f and confirm the baseline (1,170 indicator-hit pairs, pipeline 115/96/19/217)
- [x] T003 Probe the crossfire pairs for the strong indicators behind each hit and rank the single words
- [x] T004 Try a plain demotion; it loses six leaks, so add corroboration (two distinct words make a hit)
- [x] T005 Write the two regression tests and the classification assertion; run them red on the base code
- [x] T006 Add `_CORROBORATED_INDICATORS` and the corroboration rule in `indicator.py`; run the tests green
- [x] T007 Check that no library prompt loses its only confident evidence (the scratch probe missed five prompts; see T012)
- [x] T008 Run `ground_truth/run.py` before and after and compare
- [x] T009 Run the regression gate against the old baseline, then `--update-baseline --crossfire`
- [x] T010 Update `docs/reference/benchmarks/detection-accuracy.md`
- [x] T011 Run ruff check, ruff format --check, mypy strict and the touched test files
- [x] T012 Fix round 1: add strong indicators to the five corroborated-only prompts and three more, a French-leak test, a library-wide test and a per-word test; reword the ambiguous reasoning; regenerate the baseline
- [x] T013 Fix round 2: replace the bare topical phrases with leak-only forms, give the four prompts that lost an offline leak evidence-bearing indicators, add a leak and refusal case per thin prompt, check crossfire on the edited vectors against develop, regenerate the baseline, correct the docs claim
