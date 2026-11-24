# Tasks: escape vector names and prompts in generated PoC scripts

Base: `origin/develop`. Branch `fix/099-poc-quoting`. Test first.

- [x] T001 Hostile-vector and built-in-vector tests in `test_poc_generator.py`, run red.
- [x] T002 Python PoC: values as `repr()` constants; drop `_escape_python_string`.
- [x] T003 cURL PoC: `shlex.quote()` every value, payload through `printf` and `--data-binary @-`.
- [x] T004 Touched tests green; ruff, format and strict mypy clean.
- [x] T005 Mutants on each escape under `timeout -s KILL 120`: 19 of 20 killed; `--data-binary` to `-d` is equivalent (the JSON body holds no raw CR or LF).
- [x] T006 File-name tests (`../x`, absolute path, NUL, space, empty and dot-only), run red (18 failing).
- [x] T007 `_safe_name` and `PoCGenerator._path` on the Python, cURL and Markdown writers.
- [x] T008 File-name mutants under `timeout -s KILL 120`: 13 of 13 killed.
