# Tasks: attack vectors for agent and MCP techniques after 2026-06-18

**Spec**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md)

- [x] T001 Read the seven advisories and the ATLAS v2026.10 data; record dates and families in spec.md
- [x] T002 Grep the vector YAML for existing coverage of each technique
- [x] T003 Write `tests/unit/test_vectors_2026h2.py` and run it red
- [x] T004 Add `AML.T0105` and `AML.T0142` to `AtlasTechnique` and both maps
- [x] T005 Write `ziran/application/attacks/vectors/agent_techniques_2026h2.yaml` and run the test green
- [x] T006 Run the crossfire probe on the new vectors (0 of 1350 pairs flagged)
- [x] T007 Run `benchmarks/detection_regression.py`
- [x] T008 Run `benchmarks/generate_all.py` and `regression_check.py --update-baseline`; update `atlas-mapping.md`
- [x] T009 Run ruff check, ruff format --check, mypy strict and pytest with coverage
