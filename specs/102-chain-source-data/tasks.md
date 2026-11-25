# Tasks: A chain's data classes include what its source tools reach

Base: `origin/develop` at ae43713. Branch `feat/chain-source-data`. Test first.

- [x] T001 Tests in `test_blast_radius_report.py` (`TestSourceTools`): tagged source on a probe-shaped graph (reachable, demonstrated), file-to-HTTP still `secret` only, shared `sensitive_data` with no false class; run red against the base result builder: 2 failed, 2 passed.
- [x] T002 `_fill_blast_radius` walks from the last tool and the source tools of the chains ending there, one walk per last tool.
- [x] T003 Test for two chains sharing a last tool (one walk, both classes).
- [x] T004 Docstrings, report intro and `docs/reference/cli.md`.
- [x] T005 Touched tests green (`test_blast_radius.py`, `test_blast_radius_report.py`, `test_structure_import.py`, `test_scanner_size.py`, and the result builder, report and SARIF tests); ruff, format and strict mypy clean.
- [x] T006 Mutants in a `git archive` copy under `timeout -s KILL 120`.
