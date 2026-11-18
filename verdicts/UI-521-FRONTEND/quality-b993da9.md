Verdict: PASS
Gate: quality
Item: UI-521-FRONTEND
PR: taoq-ai/ziran#526
Head: b993da94e9acfe83fb874454cc73c2343ca0cc46
Confidence: medium

## Findings
- [low] tests/unit/test_no_frontend_build.py:37 blocks: no. The workflow guard only matches setup-node, "npm" and "ui/"; a step running `cd ui && yarn build` or `pnpm/action-setup` passes it (mutants M12, M13 survived). Acceptance says "needs Node.js", so other package managers would slip through; consider also matching yarn, pnpm and `cd ui`.
- [low] .dockerignore:8 blocks: no. Still lists `node_modules/`; and .github/dependabot.yml:7 comment still mentions npm advisories. Harmless leftovers.
- [low] CLAUDE.md:11 blocks: no. Auto-generated Active Technologies lines still name the React frontend (008, 009, 010); history log, not a build reference.

## Probes
- uv build in a git-archive copy of b993da9, env -i, PATH without node/npm (which node npm empty), SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0, PYTHONPATH pinned: sdist (1763 entries) and wheel (264 files) built. Wheel under ziran/interfaces has only cli/, graph_style/ and __init__.py; no static/, .js, .html, .css, ui/, hatch_build.py. The sdist holds docs/assets/ui-*.png only (docs, UI-523 owns).
- Dockerfile-equivalent context (pyproject, README, LICENSE, NOTICE, ziran/ only) with version 0+unknown builds a wheel; docker build itself not run (unmeasured), so the docker acceptance rests on CI/the builder.
- grep of the archive for hatch_build, interfaces/web/static, ui/, working-directory: ui, excluding docs, README, specs, CHANGELOG, uv.lock: only the new test and CLAUDE.md history lines. uv lock --check: resolved 212 packages, no error.
- Test run in the copy with timeout 120 (--noconftest, pytest and pyyaml only): 15 passed, 0 skipped.
- Mutants, each in a fresh copy, killed: M1 setup-node in ci.yml (test_no_workflow_step_needs_node_or_ui[ci.yml]); M2 `cd ui && npm ci` in release.yml ([release.yml]); M3 working-directory ui ([release.yml]); M10 setup-node in benchmark.yml ([benchmark.yml]); M11 `ls ui/` ([release.yml]); M4 hatch_build.py file, M4b custom hook, M5 ui/ dir, M6 docker-compose.yml (test_frontend_sources_and_build_hook_are_gone); M7 npm dependabot entry (test_dependabot_has_no_npm_entry); M8 Playwright install removed (test_playwright_install_stays_for_the_browser_adapter); M9a node FROM stage, M9b ENTRYPOINT replaced, M9c `.[ui]` (test_dockerfile_is_a_cli_image). Survived: M12 yarn, M13 pnpm (finding 1, note).
- gh pr checks 526, read once: lint, typecheck, dependency-audit, detection-accuracy gate, pentest-eval-gate and CodeQL pass; test (3.11/3.12/3.13) and integration-test were still pending at read time, so unmeasured.
- Test reaches the real files (workflows, pyproject, Dockerfile, dependabot), asserts on parsed structure rather than prose, no clock or network use.
- Simplicity: none. The 15 cases are one test per promise bullet plus a per-workflow parametrisation; nothing to delete. The diff removes more than it adds.

## Residual risk
Docker image build and the pending Python-version CI jobs were not observed at this head; a pre-existing base lag (merge-base bf85bba) means develop merges are not in this diff.
