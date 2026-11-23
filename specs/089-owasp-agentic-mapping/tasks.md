# Tasks: map attack vectors to the OWASP Top 10 for Agentic Applications

Base: `origin/develop` @ 3b0589a. Branch `feat/089-owasp-agentic-mapping`. Test first: T001 runs
red before T002.

## Phase 1 - Tests (US1)

- [x] T001 `tests/unit/test_owasp_agentic_mapping.py`: the enum and names; the built-in library
      lint is empty and every vector is mapped; the default and the explicit override in
      `_parse_vector`; the lint on a synthetic unmapped vector; results from the single,
      no-prompt, multi-turn and PAIR paths carry the field, and so does `model_dump`; the PoC
      OWASP lines show the Agentic ids.

## Phase 2 - Implementation (FR-001 to FR-006)

- [x] T002 `attack.py`: `OwaspAgenticCategory`, `OWASP_AGENTIC_DESCRIPTIONS`, the two fields.
- [x] T003 `library.py`: the default table, `_parse_vector`, `lint_owasp_agentic_coverage`.
- [x] T004 `attack_executor.py`, `tactics.py`, `pair.py`, `mcp_server_surface/scoring.py`: copy
      the field; `dynamic_vectors/generator.py`: set the category default.
- [x] T005 `poc/generator.py`: one helper for the OWASP lines.
- [x] T006 Vector YAML overrides: `supply_chain.yaml`, `mcp_attacks_expanded.yaml`,
      `agent_techniques_2026h2.yaml`, `cyberseceval_codegen.yaml`,
      `indirect_injection_tool_abuse.yaml`.

## Phase 3 - Docs and gates

- [x] T007 `docs/concepts/agent-security-landscape.md`: ASI01..ASI10 and the published names.
- [x] T008 `uv run ruff check`, `uv run ruff format --check`, `uv run mypy ziran/`, the touched
      test files and `test_scanner_size.py` under `timeout 120`; the full suite and coverage come
      from CI.
- [x] T009 Open the draft PR to `develop`.
