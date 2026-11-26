# Tasks: customer-support abuse vectors

**Spec**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md)

- [x] T001 Grep the vector YAML for refund, goodwill, discount, coupon and identity-verification coverage
- [x] T002 Fetch each source URL and record it in spec.md
- [x] T003 Write `tests/unit/test_customer_care_vectors.py` and run it red
- [x] T004 Write `ziran/application/attacks/vectors/customer_care.yaml` and run the test green
- [x] T005 Run the vector fitness and mapping tests
- [x] T006 Run `benchmarks/generate_all.py` and `regression_check.py --update-baseline`; update `README.md`, `atlas-mapping.md` and `attack-library.md`
- [x] T007 Run ruff check, ruff format --check and mypy strict
- [x] T008 Gate round 1: WSTG URLs moved to wstg.owasp.org, prompts reworded away from small numbers and field names, own-customer paging and field cases added to the test
