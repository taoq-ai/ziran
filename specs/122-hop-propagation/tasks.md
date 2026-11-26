# Tasks: hop-tagged canaries

**Spec**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md)

- [x] T001 Read `MultiAgentScanner`, the discoverer, the topology entities, the side-effect goal judge, probe markers and each adapter's `get_state`
- [x] T002 Write `tests/unit/test_hop_propagation.py` and run it red (collection error: no `propagation` module; then 3 failed with the scanner and CLI wiring stashed)
- [x] T003 Add `HopEvidence`, `LeakedPart` and `PropagationTrace` to the multi-agent entities
- [x] T004 Add `ziran/application/multi_agent/propagation.py` (`hop_canary`, `trace_propagation`)
- [x] T005 Wire `trace_hops` into `MultiAgentScanner`, add `EdgeType.PROPAGATES_TO` and the summary block; pass `trace_hops=False` in the two old tests that drive `AsyncMock` adapters
- [x] T006 Print the furthest hop and write `propagation.json` in `ziran multi-agent-scan`
- [x] T007 Run the new and touched tests green
- [x] T008 Document hop tracing in `docs/concepts/multi-agent.md`
- [x] T009 Run ruff check, ruff format --check and mypy strict
