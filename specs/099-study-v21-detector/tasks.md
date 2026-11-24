# Tasks: the study-v2.1 detector changes

Base: `origin/develop` at `1adc751`. Branch `feat/study-v21-detector`. Test first.

- [x] T001 Drift round at `1adc751`: no design-half B1 or B2 row moves, B3 and B4 counts equal.
- [x] T002 B1 hunt on the design half, no send: no general rule found; reported.
- [x] T003 Change 1 tests in `tests/unit/test_role_typing_verb_rule.py`, run red.
- [x] T004 Change 1 in `role_typing.py`; old-contract tests updated; green.
- [x] T005 Change 1 mutants: last verb, no MCP strip, no toolkit strip, no-verb clause.
- [x] T006 Change 9 tests red, fix, mutants (fragment match, file order, shortest first).
- [x] T007 Changes 2, 4 and 6 tests red, fix, mutants.
- [x] T008 Change 3 tests red, prompt v1, fix, mutants (16 of 16), as amendment 1 settles it.
- [x] T009 Change 7 tests red, fix, mutants, detection benchmark before and after.
- [ ] T010 Change 8 tests red, fix, mutants, the early check with no send.
- [ ] T011 Ruff, format, strict mypy, the whole test suite.
