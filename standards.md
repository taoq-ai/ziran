# Standards

WIP limit: 1 (owner, 2026-11-18)

## Gates and builders
- When you touch anything under `ziran/application/agent_scanner/` or `ziran/application/attacks/`, also run `tests/unit/application/test_scanner_size.py` (400-line module budget, 750 for scanner.py). It escaped twice on 2026-11-18 (#524, #531).
- Never run the full test suite locally (owner, 2026-11-18). Run only the test files for the code you touch (`uv run pytest tests/<the touched test files>`); full-suite pass and the 85% coverage figure come from CI only. Read them from `gh pr checks`, never re-run them locally.
- Run every mutant or probe test under a hard timeout (`timeout 120 uv run pytest ...`) and kill its processes before handing back. A removed loop guard hangs forever and grows memory (two orphaned runs reached 50 GB each, 2026-11-18).
