Verdict: PASS
Gate: quality
Item: UI-522-BACKEND
PR: taoq-ai/ziran#525
Head: 28f42d8c5b368d69b3547fcb8820a4897f299fa9
Confidence: medium
Breaking: no

## Findings
- [low] tests/unit/test_phase_graph_persistence.py:19 blocks: no. The kept test adds the vulnerability node through add_edge as well as add_vulnerability; with add_vulnerability's own add_node removed the test still passes (networkx creates the node from the edge). It asserts real graph behaviour (a mutant dropping nodes from export_state fails it) but add_vulnerability itself is not pinned here.
- [low] Dockerfile:18 blocks: no. Dockerfile still runs pip install ".[ui]" and CMD ziran ui, so the image would build without the extra and its default command would exit 2; outside this item's file list, belongs with the frontend removal (#521) or docs (#523) work.
- [low] blocks: no. Coverage is unmeasured at this head: test (3.11), test (3.12), test (3.13) were still pending when gh pr checks 525 was read once; integration-test, lint, typecheck, dependency-audit passed.

## Probes
Copy: git archive 28f42d8 into the scratchpad folder sentinel-quality-UI-522, PYTHONPATH pinned to it, venv from uv sync --frozen --extra streaming (SETUPTOOLS_SCM_PRETEND_VERSION set).
Acceptance grep `grep -rn "interfaces.web\|ziran\[ui\]" ziran tests pyproject.toml`: empty (rc 1).
uv lock --check: passes (Resolved 212 packages).
uv sync --extra streaming: installs websockets 16.1.1; import of WebSocketProtocolHandler works from the copy.
Real CLI: `ziran ui --host x --port 1 --dev` prints the notice to stderr, exit 2; also via the installed entry point.
Tests run under timeout 120: test_cli_smoke, test_ws_handler, test_cicd_suppressions, test_phase_graph_persistence: 111 passed, 0 skipped.
Skips: the only importorskip of a removed package is tests/integration/test_promptfoo_integration.py (fastapi, uvicorn); the builder added both to the test dependency group, and CI syncs `--group test --extra all`, so it does not skip silently. The importorskip("websockets") in the new ws test is satisfied by the streaming extra in `--extra all`; no fastapi, sqlalchemy, asyncpg or alembic skips remain.
Mutants (each failed a test): ui exit 2 -> 0 (test_ui_prints_moved_notice_and_exits_2); hidden=True -> False (test_ui_hidden_from_help); notice text changed (same test); echo removed (same test); gate.py attack_fingerprint args swapped (test_attack_fingerprint_pinned, the new ci-side assertion); ws_handler `import websockets` broken (test_connect_uses_installed_websockets); streaming pin <18 -> <19, streaming dropped from all, ui added to all (test_streaming_extra_declares_websockets); export_state dropping nodes (test_snapshots_are_monotonic_supersets). Surviving: add_vulnerability add_node removed, and cache invalidation removed there (add_edge covers both): reported as the low note above, untested rather than deletable.
Closed: none (first round).
Simplicity: none to delete; the stub is a short command and the test dependencies are what the promptfoo live-server test needs.
Coverage: CI uses --cov-fail-under=80 in test.yml (the 85% figure is the project standard); the diff removes about 3,500 lines of web code and its tests together, so the ratio is unlikely to drop, but this is unmeasured until the test jobs finish.

## Residual risk
Coverage and the three test matrix jobs had not finished when read once; the integration job passed. The Dockerfile and README still point at the removed ui extra (docs and frontend items).
