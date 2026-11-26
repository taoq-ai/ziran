# Tasks: spec 121

- [x] T001 Add tests (2 of 3 flaky through SARIF and reports, k = 1 pin, cache trial keys, per-trial probe markers, trials < 1 refused, CLI flag); run red
- [x] T002 Add `trials.py` and wire `PhaseExecutor`, `AttackExecutor`, `ScanCache`, `AgentScanner`, CLI; run green
- [x] T003 SARIF properties and Markdown and HTML labels
- [x] T004 Check consumers; docs row in `docs/reference/cli.md`
- [x] T005 ruff check, ruff format --check, mypy strict, size caps
- [x] T006 Gate round 1: serial phase and k-scaled timeout at k > 1, per-run unmeasured on error or timeout, cost cap per run; tests for each (red, then green)
