# Tasks: escape vector names and prompts in generated PoC scripts

Base: `origin/develop`. Branch `fix/099-poc-quoting`. Test first.

- [x] T001 Hostile-vector and built-in-vector tests in `test_poc_generator.py`, run red.
- [x] T002 Python PoC: values as `repr()` constants; drop `_escape_python_string`.
- [x] T003 cURL PoC: `shlex.quote()` every value, payload through `printf` and `--data-binary @-`.
- [x] T004 Touched tests green; ruff, format and strict mypy clean.
- [ ] T005 Mutants on each escape under `timeout -s KILL 120`, all killed.
