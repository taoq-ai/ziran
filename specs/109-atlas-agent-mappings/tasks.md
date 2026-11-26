# Tasks: MITRE ATLAS agent techniques and OWASP Agentic ASI08 to ASI10 mappings

Base: `origin/develop` @ f533d8e. Branch `feat/109-atlas-agent-mappings`. Test first: T001 runs
red before T002.

## Phase 1 - Tests (US1, US2)

- [x] T001 `tests/unit/test_atlas_agent_techniques.py`: each id's name and tactics as in ATLAS
      2026.10; one exact vector set per technique; every listed vector exists; the multi-agent
      default and the eight YAML overrides.

## Phase 2 - Implementation (FR-001 to FR-003)

- [x] T002 `ziran/domain/entities/attack.py`: twelve `AtlasTechnique` members, names, tactics.
- [x] T003 Vector YAML: append the ids in the spec's mapping table to `atlas_mapping`.
- [x] T004 `ziran/application/attacks/library.py`: `MULTI_AGENT: [ASI07, ASI08]`; YAML
      overrides in `multi_agent.yaml`, `a2a_attacks.yaml`, `mcp_server_surface.yaml`.

## Phase 3 - Coverage reference and gates (US3, FR-004)

- [x] T005 Run `benchmarks/generate_all.py` and `benchmarks/regression_check.py
      --update-baseline`; commit `benchmarks/README.md`, `coverage-comparison.md`,
      `baseline.json`.
- [x] T006 `docs/reference/benchmarks/atlas-mapping.md` (counts, agent technique table, gaps),
      `docs/concepts/agent-security-landscape.md` (ASI08 to ASI10), README count.
- [x] T007 `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`, the
      touched test files and `test_scanner_size.py` under `timeout`; the full suite and coverage
      come from CI.
- [x] T008 Open the draft PR to `develop`.
