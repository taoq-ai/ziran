# Tasks: policy export escapes tool names and emits OPA 1.0 Rego

Base: `origin/develop` at d1fa050. Branch `fix/107-policy-export-escaping`. Test first.

- [x] T001 Add `cedarpy` to the `test` dependency group (`uv add --group test`).
- [x] T002 Test: a hostile tool set (quote, backslash, newline, closing brace, a whole Rego
  rule, a Cedar `};`, U+2028, NEL) through every renderer, with a hostile finding id and
  vulnerability type (`tests/unit/test_policy_renderer_escaping.py`); the Rego test expects
  `deny contains msg if {`. Run red: 8 failed, 2 opa tests skipped without the binary.
- [x] T003 Escape every value in the four renderers; Rego moves to OPA 1.0 syntax.
- [x] T004 Touched tests green (56 passed, 2 skipped locally); ruff, format and mypy clean.
- [x] T005 `setup-opa` in `test.yml` and `release.yml`; research.md Rego line updated.
- [x] T006 Security fix round at 84e7935. Test: an astral U+1F50D in `HOSTILE`, a Cedar lone
  surrogate that fails closed, a chain with no tools, a `../` campaign id through the CLI. Run
  red: 4 failed (Colang, Invariant, empty chain, path); the Cedar pin passed as it stands.
- [x] T007 `quoted` in `ziran/domain/text.py` for Colang and Invariant; `_rego_str` keeps
  printable characters raw; `ExportService` skips empty chains; the CLI sanitises file names
  and escapes verbose lines; one docs line on the OPA version. Touched tests: 74 passed,
  2 skipped (opa locally).
