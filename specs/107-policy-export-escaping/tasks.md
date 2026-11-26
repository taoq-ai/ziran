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
