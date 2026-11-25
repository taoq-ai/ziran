# Tasks: A generated PoC reads a deeply nested live reply without a traceback

Base: `origin/develop` at ae43713. Branch `fix/poc-live-reply-depth`. Test first.

- [x] T001 Stub `raw` override and tests in `test_poc_target_protocol.py` (deep replies at 5000 and 100000 on both protocols, the generated `_texts` walk, the cURL PoC); run red against the base generator: 6 failed, 2 passed.
- [x] T002 Iterative `_texts`; `RecursionError` from `reply.json()` prints the message and exits 3; usage text lists exit 3.
- [x] T003 Docs: `docs/reference/cli.md` exit-code line.
- [x] T004 Touched tests green on 3.14 (`test_poc_target_protocol.py`, `test_poc_generator.py`: 117 passed, 1 skipped) and on 3.11 (the new tests: 8 passed); ruff, format and mypy clean.
- [x] T005 Mutants in an archive copy under `timeout -s KILL 120`: 5 of 5 killed.
