# Plan: A generated PoC reads a deeply nested live reply without a traceback

No new dependency.

- `ziran/application/poc/generator.py`, `_PY_HTTP_REPRODUCE` (the httpx Python PoC body):
  `_texts` becomes an iterative stack walk (reversed push keeps document order);
  `reproduce` catches `RecursionError` from `reply.json()`, prints the message and returns 3.
  The usage text and the `reproduce` docstring list exit 3.
- The cURL script, the adapter-driven Python body, `_indicators` and the request builder are
  untouched.
- Docs: the exit-code line in `docs/reference/cli.md`.

Tests in `tests/unit/test_poc_target_protocol.py`: the stub gains a `raw` body override. A
parametrized test runs the Python PoC under `python -I` against 5000-deep and 100000-deep
replies on both stub protocols; a unit test loads the generated script with `runpy` (not as
`__main__`, so it sends nothing) and walks a 5000-deep value and a mixed dict and list; a
cURL test checks the deep reply still reproduces.
