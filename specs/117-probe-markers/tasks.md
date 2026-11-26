# Tasks: per-probe correlation markers

**Spec**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md)

- [x] T001 Grep `ziran/` for an existing marker; trace the HTTP adapter's client, the four protocol handlers and every `AttackResult` path through `AttackExecutor.execute`
- [x] T002 Write `tests/unit/test_probe_markers.py` and run it red (11 failed)
- [x] T003 Add `TargetConfig.probe_markers`, `ProbeMarker` and `AttackResult.probe_markers`
- [x] T004 Add `ziran/domain/probe_markers.py` (`probe_scope`, `mark_probe`)
- [x] T005 Hook `HttpAgentAdapter` (client request hook, `invoke`, `stream`) and `AttackExecutor.execute`; pass the campaign id from `AgentScanner`
- [x] T006 Run the new tests green, the off-path pin on the base commit, and the touched-path tests
- [x] T007 Document `probe_markers` in `docs/guides/remote-agents.md`
- [x] T008 Run ruff check, ruff format --check and mypy strict
