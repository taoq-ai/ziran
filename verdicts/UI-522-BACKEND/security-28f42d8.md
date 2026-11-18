Verdict: PASS
Gate: security
Item: UI-522-BACKEND
PR: taoq-ai/ziran#525
Head: 28f42d8c5b368d69b3547fcb8820a4897f299fa9
Confidence: high

## Findings
- [low] docker-compose.yml:7 blocks: no. Existing gap, not in this diff: the dev compose runs Postgres with the default password `postgres` and publishes 5432 on every host interface; the Dockerfile (line 20) bakes the same credential into ZIRAN_DATABASE_URL and still installs `.[ui]` and runs `ziran ui`, which now exits 2. No workflow builds or publishes the image. #521 removes both files' UI parts; flag it there so the db service goes too.
- [low] .env.example:6 blocks: no. A commented ZIRAN_DATABASE_URL with default credentials is left over and nothing reads it now. README.md:141 and :236-237 still tell users to `pip install ziran[ui]` and run `ziran ui`. Docs cleanup only, no secret handling left behind.

## Probes
- Scope: `git diff --name-only origin/develop...28f42d8` lists pyproject.toml, uv.lock, ws_handler.py (docstring only), html_report.py and graph_style/spec.py (comments), cli/main.py (ui stub), ziran/interfaces/web/ (all deleted), tests, and specs/083. No workflow, action or install-script changes. The merge base is origin/develop c7da589.
- Lockfile: `git diff origin/develop...28f42d8 -- uv.lock`. The removed packages are alembic 1.18.4, asyncpg 0.31.0, mako 1.4.2 and psycopg2-binary 2.9.12. The added lines are references only: the streaming extra, the websockets marker/specifier, fastapi and uvicorn in the test group, and provides-extras. No version, source or hash lines were added. websockets stays at 16.1.1, fastapi 0.138.0, uvicorn 0.49.0 and starlette 1.3.1, all already locked.
- pip-audit, run as CI does on a `git archive` copy: `uv export --frozen --no-emit-project --all-extras`, then `uvx pip-audit --no-deps --disable-pip` with CI's 7 --ignore-vuln flags. Result: "No known vulnerabilities found, 8 ignored".
- websockets range >=12.0,<18: pip-audit finds no known vulnerabilities in 12.0, 13.1, 14.2, 15.0.1 or 16.0. The known-positive control, websockets 9.0, reports PYSEC-2021-95 (fixed in 9.1), so the scanner is live and the range floor sits above the only known advisory.
- ziran ui stub, run with `python -I` and an audit hook in the archived tree, stdin set to /dev/null: `ui`, `ui --host 0.0.0.0 --port 8484 --dev extra`, and `ui` with ZIRAN_DATABASE_URL set. Every run exits 2 and prints the notice on stderr only (0 stdout bytes from the real `ziran ui --port 1`). No socket, input or subprocess audit events fired, and no uvicorn, fastapi or ziran.interfaces.web module was loaded. The stub's code reads no env and no input; it calls click.echo(err=True) and raises SystemExit(2). It is absent from `ziran --help` (0 matches).
- Mutant: SystemExit(2) changed to SystemExit(0) in a fresh copy (mut1). TestUIMovedStub fails 2 of 3, so it is killed. No other guard or validation changed.
- Targeted tests at head: test_ws_handler.py and test_cli_smoke.py, 36 passed. The streaming test checks the extra is declared and that the adapter connects through the installed websockets.
- Dangling secret handling: grep for ZIRAN_DATABASE_URL, POSTGRES_PASSWORD, asyncpg, postgres URLs, ziran[ui] and interfaces.web outside uv.lock and specs. Only the docs and dev files listed under Findings, the CLAUDE.md history lines, intentional fixtures (an example agent and an attack vector) and the stub's test docstring remain. No code in ziran/ reads a DB credential now.
- Dev test group (fastapi, uvicorn): dev-only under [dependency-groups], not in the wheel's Requires-Dist. Its one user, tests/integration/test_promptfoo_integration.py:41, binds 127.0.0.1.
- Confidence is high: all checks above ran at the exact head and the PR head matches 28f42d8 (draft). It would drop if CI's pip-audit at the PR shows a new advisory published after this run.
- Processes: none left running; probes used timeout.

## Residual risk
Removing the code shrinks the attack surface: the FastAPI routes, DB credentials, migrations and WebSocket server are gone. The compose default Postgres password stays live until #521 lands.
