# Tasks: A2A identity probes

**Spec**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md)

- [x] T001 Read the A2A handler, `A2AAgentCard`, the scan path (`PhaseExecutor`, `AttackExecutor`, `ResultBuilder`), the A2A 1.0 signing, `SendMessage` and `GetTask` text, and the a2a-sdk signer
- [x] T002 Write `tests/a2a_servers.py`, `tests/unit/test_a2a_probe.py` and `tests/integration/test_a2a_identity_scan.py`; run them red
- [x] T003 Add the domain fields, the `a2a_probe` field and validator, and the `A2AWire` port
- [x] T004 Add `HttpA2AWire` and `HttpAgentAdapter.a2a_wire`
- [x] T005 Add `ziran/application/a2a_probe/` (probes and JWS check) and the executor and phase hooks
- [x] T006 Add `vectors/a2a_identity.yaml`; run the new tests green
- [x] T007 Update the tests of the old contract (every vector has a prompt; phase vector counts on a mock target)
- [x] T008 Regenerate benchmarks and baseline; update README, attack-library and atlas-mapping counts; document the field and the probes
- [x] T009 Run ruff check, ruff format --check and mypy strict; run the new, touched and fitness tests
