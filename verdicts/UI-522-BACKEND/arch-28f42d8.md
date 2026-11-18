Verdict: PASS
Gate: arch
Item: UI-522-BACKEND
PR: taoq-ai/ziran#525
Head: 28f42d8c5b368d69b3547fcb8820a4897f299fa9
Confidence: medium
Breaking: yes: the `ui` extra is gone (pip warns and installs ziran without it), `ziran ui` no longer serves the dashboard and exits 2, and the `ziran.interfaces.web` modules can no longer be imported; nothing else in the CLI, library, extras or entry points changes (announced in #520)

## Findings
- [low] Dockerfile:18 blocks: no. In the window before #521, `pip install ".[ui]"` still builds (pip warns that the extra is unknown), but the container runs `ziran ui` and exits 2, and docker-compose's ziran-ui service stops. No workflow builds the image, and the release waits for #521, #522 and #523. The PR body records this under Assumptions.
- [low] hatch_build.py:15 blocks: no. Until #521 lands, a `uv build` (release.yml:155) still compiles ui/ into ziran/interfaces/web/static/ and ships it as dead assets in the wheel. The release-ordering rule in #520 covers this. #521 has to delete the hook together with ui/.
- [low] ziran/interfaces/cli/main.py:2841 blocks: no. `ziran ui --help` exits 0 with "Removed: print where the web UI went and exit 2." and does not show the notice. Only `ziran ui` with other arguments prints the notice. This is acceptable for a one-release stub.
- [low] blocks: no. Spec number 083 is used only by this branch. No #521 or #523 branch exists yet, so those items must take 084 and 085.
- [low] blocks: no. Coverage is unmeasured at this head: the test (3.11/3.12/3.13) jobs were still pending when read. CI enforces fail_under=80 (pyproject.toml:241, test.yml:54), and the item states 85. Removing the well-covered web modules shrinks the covered numerator, so the goal and quality gates should read the CI result.

## Probes
- Tree copy: `git archive 28f42d8` into scratchpad/sentinel-arch-UI-522/tree, then `uv sync --frozen --group test --extra streaming`.
- Leftover references: `grep -rn "interfaces.web|interfaces/web|ziran[ui]|.[ui]|ziran ui"` outside specs/ finds only ui/vite.config.ts, Dockerfile, .gitignore and README (owned by #521 and #523). There are none in ziran/, tests/, benchmarks/, examples/, action.yml, docs/ or mkdocs.yml, and docs have no mkdocstrings `::: ziran.interfaces.web` entry. Python API: `pkgutil.walk_packages(ziran)` finds no web module. The only entry point is `ziran = ziran.interfaces.cli.main:cli`.
- Imports of removed deps (`grep -rnE "^(import|from) (websockets|fastapi|uvicorn|starlette|sqlalchemy|asyncpg|alembic|psycopg)"` over ziran, tests, benchmarks, examples): websockets appears only in ws_handler.py:30 (TYPE_CHECKING) and :111 (lazy), so the `streaming` extra covers every WebSocket path. fastapi appears only in examples/15 vulnerable_server.py.
- promptfoo: ziran/integrations/promptfoo imports neither fastapi nor uvicorn. Only tests/integration/test_promptfoo_integration.py needs them, to serve examples/15. The `promptfoo` extra is empty, so moving fastapi and uvicorn to the dev `test` group is correct and no user path needs them.
- Lock: `uv lock --check` resolves 212 packages and is consistent. uv.lock:5847-5848 carries websockets under both `extra == 'all'` and `extra == 'streaming'`. The lock diff drops only alembic, asyncpg, mako and psycopg2-binary. `uvicorn[standard]` became `uvicorn` with the same range.
- CLI: `ziran --help` lists the 17 commands without `ui`. The main.py diff touches only the ui block. `ziran ui --host 0.0.0.0 --dev` prints the notice and returns rc=2.
- Hexagonal rule (constitution I): one driving adapter is removed and no inner layer imported it. The infrastructure ws_handler is unchanged apart from its docstring. No new dependency edge.
- Tests (timeout 120, --no-cov): test_ws_handler, test_cli_smoke, test_cicd_suppressions, test_phase_graph_persistence, test_html_report, test_graph_style_spec and the promptfoo integration test gave 199 passed.
- Mutants, re-run from a restored file each time: SystemExit(2) to (1) fails 2 tests in test_cli_smoke. hidden=False fails test_ui_hidden_from_help. Removing streaming from `all` fails test_streaming_extra_declares_websockets. Dropping ignore_unknown_options fails the parametrized flags case. No survivors.
- CI (`gh pr checks 525`, read once): lint, typecheck, integration-test, dependency-audit, CodeQL, action tests and frontend-build pass. test (3.11/3.12/3.13) are pending.
- The PR body's Assumptions record the two-way choices: the starlette override, the fastapi/uvicorn move, the stub ignoring arguments, and Docker left for #521.
- Confidence is medium because the coverage matrix is pending. High would need the test jobs green with coverage at or above the threshold.

## Residual risk
Until #521 merges, develop holds a Dockerfile, a build hook and a .gitignore entry that point at the removed package. Releasing from develop before #521 and #523 merge would ship a broken image and dead wheel assets.
