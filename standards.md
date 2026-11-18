# Standards

WIP limit: 1 (owner, 2026-11-18)

## Gates and builders
- Archive copies (retro 2026-11-18): in a `git archive` copy set `SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0` before `uv sync`/`uv build`, pin `PYTHONPATH` to the copy and check `ziran.__file__` points inside it, run ruff on named folders (`ziran tests benchmarks scripts`) not `.`, and read git-dependent tests (`test_external_eval_*`, hybrid prompt base) from CI.

## Planner and lead (retro 2026-11-18)
- Derive the next spec number from `git ls-tree origin/develop specs/` plus `git branch -r`, never by guess.
- Give a release gate its range as `git log --first-parent origin/main..<head>`, not a list of items.
- Before sizing an item that touches agent_scanner or attacks, measure module headroom against `test_scanner_size.py` (400 / 750 lines) and put it in the brief (scanner.py is at 746/750 on 2026-11-18).
- Verify every external fact in a promise (API endpoints, advisory dates, counts) before it reaches a builder.
- When you touch anything under `ziran/application/agent_scanner/` or `ziran/application/attacks/`, also run `tests/unit/application/test_scanner_size.py` (400-line module budget, 750 for scanner.py). It escaped twice on 2026-11-18 (#524, #531).
- Never run the full test suite locally (owner, 2026-11-18). Run only the test files for the code you touch (`uv run pytest tests/<the touched test files>`); full-suite pass and the 85% coverage figure come from CI only. Read them from `gh pr checks`, never re-run them locally.
- Run every mutant or probe test under a hard timeout (`timeout 120 uv run pytest ...`) and kill its processes before handing back. A removed loop guard hangs forever and grows memory (two orphaned runs reached 50 GB each, 2026-11-18).
